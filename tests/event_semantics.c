#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void pause_collector(void) { usleep(150000); }

static void die(const char *message) {
  perror(message);
  exit(1);
}

static void set_name(const char *name) {
  if (prctl(PR_SET_NAME, name, 0, 0, 0) != 0)
    die("prctl");
  pause_collector();
}

static int open_file(const char *dir, const char *name) {
  char path[1024];
  if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int)sizeof(path)) {
    fprintf(stderr, "fixture path too long\n");
    exit(1);
  }
  int fd = open(path, O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0)
    die("open fixture file");
  pause_collector();
  return fd;
}

static void check_write(const char *name, int fd, long syscall_id,
                        const void *buf, size_t size, long expected) {
  struct iovec iov[2] = {
      {.iov_base = (void *)buf, .iov_len = size / 2},
      {.iov_base = (char *)buf + size / 2, .iov_len = size - size / 2},
  };
  set_name(name);
  errno = 0;
  long ret;
  if (syscall_id == SYS_writev)
    ret = syscall(SYS_writev, fd, iov, 2);
  else if (syscall_id == SYS_pwrite64)
    ret = syscall(SYS_pwrite64, fd, buf, size, 0);
  else
    ret = syscall(SYS_write, fd, buf, size);
  long result = ret < 0 ? -errno : ret;
  if (result != expected) {
    fprintf(stderr, "%s: result=%ld expected=%ld\n", name, result, expected);
    exit(1);
  }
  pause_collector();
  printf("write\t%s\t%d\t%d\t%ld\t%zu\t%d\t%ld\n", name,
         (int)getpid(), fd, syscall_id, size, syscall_id == SYS_writev ? 2 : 0,
         result);
  fflush(stdout);
  pause_collector();
}

static void check_partial_pipe(const char *name, long syscall_id) {
  int fds[2];
  if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0)
    die("pipe2");
  int capacity = fcntl(fds[1], F_SETPIPE_SZ, 4096);
  if (capacity < 4096)
    die("F_SETPIPE_SZ");
  size_t size = (size_t)capacity * 2;
  char *buf = malloc(size);
  if (!buf)
    die("malloc pipe buffer");
  memset(buf, 'p', size);
  // With no reader draining an empty nonblocking pipe, this fills it exactly.
  check_write(name, fds[1], syscall_id, buf, size, capacity);
  free(buf);
  close(fds[0]);
  close(fds[1]);
  pause_collector();
}

static void failed_exec(const char *dir, const char *name,
                        const char *target, int expected_errno) {
  char path[1024];
  if (snprintf(path, sizeof(path), "%s/%s", dir, target) >=
      (int)sizeof(path)) {
    fprintf(stderr, "missing-exec path too long\n");
    exit(1);
  }
  set_name(name);
  char *args[] = {path, NULL};
  execve(path, args, environ);
  if (errno != expected_errno)
    die("exec failed with unexpected errno");
  pause_collector();
  printf("exec-failure\t%s\t%d\t%s\n", name, (int)getpid(), path);
  fflush(stdout);
  pause_collector();
}

static void failed_open(const char *dir) {
  char path[1024];
  if (snprintf(path, sizeof(path), "%s/missing-open.data", dir) >=
      (int)sizeof(path)) {
    fprintf(stderr, "missing-open path too long\n");
    exit(1);
  }
  set_name("ev-open-fail");
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd >= 0 || errno != ENOENT) {
    fprintf(stderr, "expected open of missing fixture to fail with ENOENT\n");
    exit(1);
  }
  pause_collector();
  printf("open-failure\tev-open-fail\t%d\t%d\t%s\n", (int)getpid(),
         -ENOENT, path);
  fflush(stdout);
  pause_collector();
}

static void concurrent_writes(const char *dir) {
  int gate[2];
  pid_t children[4];
  if (pipe2(gate, O_CLOEXEC) != 0)
    die("concurrency gate");
  fflush(stdout);
  for (int i = 0; i < 4; i++) {
    children[i] = fork();
    if (children[i] < 0)
      die("fork writer");
    if (children[i] == 0) {
      close(gate[1]);
      char token;
      if (read(gate[0], &token, 1) != 1)
        die("read writer gate");
      close(gate[0]);
      char name[16];
      char file[32];
      snprintf(name, sizeof(name), "ev-con-%d", i);
      snprintf(file, sizeof(file), "concurrent-%d.data", i);
      set_name(name);
      int fd = open_file(dir, file);
      char data[64];
      memset(data, 'a' + i, sizeof(data));
      check_write(name, fd, SYS_write, data, 31 + i, 31 + i);
      close(fd);
      pause_collector();
      _exit(0);
    }
  }
  close(gate[0]);
  if (write(gate[1], "go!!", 4) != 4)
    die("release writer gate");
  close(gate[1]);
  for (int i = 0; i < 4; i++) {
    int status;
    pid_t waited;
    do {
      waited = waitpid(children[i], &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != children[i] || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      fprintf(stderr, "concurrent writer %d failed\n", i);
      exit(1);
    }
  }
}

int main(int argc, char **argv) {
  if (argc != 2 && argc != 3) {
    fprintf(stderr, "usage: event_semantics [--after-exec|--trusted-fail|--spoof-trusted|--failed-open] DIR\n");
    return 2;
  }
  const char *dir = argv[argc - 1];
  char buf[8192];
  memset(buf, 'x', sizeof(buf));

  if (argc == 3 && strcmp(argv[1], "--after-exec") == 0) {
    set_name("ev-after-exec");
    int fd = open_file(dir, "after-exec.data");
    check_write("ev-after-exec", fd, SYS_write, buf, 13, 13);
    close(fd);
    pause_collector();
    return 0;
  }
  if (argc == 3 && strcmp(argv[1], "--trusted-fail") == 0) {
    failed_exec(dir, "ev-trusted", "missing-executable", ENOENT);
    int fd = open_file(dir, "trusted-after-failure.data");
    check_write("ev-trusted", fd, SYS_write, buf, 13, 13);
    close(fd);
    // Keep procfs identity available until the collector consumes the events.
    usleep(500000);
    return 0;
  }
  if (argc == 3 && strcmp(argv[1], "--spoof-trusted") == 0) {
    failed_exec(dir, "ev-spoof", "trusted-not-executable", EACCES);
    int fd = open_file(dir, "spoof-after-failure.data");
    check_write("ev-spoof", fd, SYS_write, buf, 13, 13);
    close(fd);
    usleep(500000);
    return 0;
  }
  if (argc == 3 && strcmp(argv[1], "--failed-open") == 0) {
    failed_open(dir);
    check_write("ev-open-fail", -1, SYS_write, buf, 13, -EBADF);
    return 0;
  }
  if (argc != 2)
    return 2;

  failed_open(dir);
  set_name("ev-setup");
  int fd = open_file(dir, "writes.data");
  check_write("ev-w-ok", fd, SYS_write, buf, 17, 17);
  check_write("ev-pw-ok", fd, SYS_pwrite64, buf, 19, 19);
  check_write("ev-wv-ok", fd, SYS_writev, buf, 23, 23);
  check_write("ev-w-zero", fd, SYS_write, buf, 0, 0);
  check_write("ev-w-bad", -1, SYS_write, buf, 17, -EBADF);
  check_write("ev-pw-bad", -1, SYS_pwrite64, buf, 19, -EBADF);
  check_write("ev-wv-bad", -1, SYS_writev, buf, 23, -EBADF);
  close(fd);
  pause_collector();

  check_partial_pipe("ev-w-part", SYS_write);
  check_partial_pipe("ev-wv-part", SYS_writev);

  // A file-size limit produces a deterministic partial positional write.
  set_name("ev-setup");
  fd = open_file(dir, "partial-pwrite.data");
  struct rlimit original;
  if (getrlimit(RLIMIT_FSIZE, &original) != 0)
    die("getrlimit");
  struct rlimit bounded = original;
  bounded.rlim_cur = 4096;
  if (setrlimit(RLIMIT_FSIZE, &bounded) != 0)
    die("setrlimit partial pwrite");
  check_write("ev-pw-part", fd, SYS_pwrite64, buf, sizeof(buf), 4096);
  if (setrlimit(RLIMIT_FSIZE, &original) != 0)
    die("restore RLIMIT_FSIZE");
  close(fd);
  pause_collector();

  set_name("ev-setup");
  concurrent_writes(dir);
  failed_exec(dir, "ev-exec-fail", "missing-executable", ENOENT);
  set_name("ev-before-exec");
  printf("exec-target\tev-before-exec\t%d\t%s\n", (int)getpid(), argv[0]);
  fflush(stdout);
  pause_collector();
  char *args[] = {argv[0], "--after-exec", (char *)dir, NULL};
  execve(argv[0], args, environ);
  die("re-exec fixture");
}
