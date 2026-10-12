package sensor

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCoreBPFDoesNotReadArchitectureSpecificRegisters(t *testing.T) {
	source, err := os.ReadFile("../../bpf/ransomware.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	// The checked-in vmlinux.h is x86-derived. The shared core object remains
	// portable only while kprobe registers are opaque and fields use CO-RE.
	registerAccess := regexp.MustCompile(`\bctx\s*->\s*(ax|di|si|dx|regs|sp|orig_ax)\b|\bPT_REGS_[A-Z_]+\b`)
	if match := registerAccess.Find(source); match != nil {
		t.Fatalf("core object embeds architecture-specific register decoding: %s", match)
	}
}

func TestBPFLSMPrototypeAndPriorDenial(t *testing.T) {
	source, err := os.ReadFile("../../bpf/ransomware.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	for name, arguments := range map[string]int{
		"enforce_file_open":           2,
		"enforce_file_permission":     3,
		"enforce_path_truncate":       2,
		"enforce_path_rename":         6,
		"enforce_path_rename_legacy":  5,
		"enforce_inode_rename":        5,
		"enforce_path_mknod":          5,
		"enforce_inode_create":        4,
		"enforce_path_unlink":         3,
		"enforce_bprm_check_security": 2,
	} {
		t.Run(name, func(t *testing.T) {
			declaration, body := cSourceFunction(t, string(source), "int BPF_PROG("+name+",")
			if got := strings.Count(declaration, ","); got != arguments {
				t.Fatalf("hook plus chained return arguments=%d, want %d: %s", got, arguments, declaration)
			}
			if !strings.HasSuffix(strings.TrimSpace(declaration), "int ret)") {
				t.Fatalf("hook does not declare its chained return value: %s", declaration)
			}
			if name == "enforce_path_rename" || name == "enforce_path_rename_legacy" {
				if !strings.Contains(body, "return enforce_path_rename_common(new_dir, new_dentry, ret);") {
					t.Fatal("rename variant does not forward the chained return")
				}
				_, body = cSourceFunction(t, string(source), "static __always_inline int enforce_path_rename_common(")
			}
			body = strings.Join(strings.Fields(body), " ")
			body = strings.TrimSpace(strings.TrimPrefix(body, "struct block_entry *entry;"))
			if !strings.HasPrefix(body, "if (ret) return ret;") {
				t.Fatal("hook must preserve a previous denial before policy checks or side effects")
			}
		})
	}
	if strings.Contains(string(source), "return enforce_inline_ioc(") {
		t.Fatal("observe-only inline IOC must not bypass an existing process block")
	}
}

func TestBPFKernelDeviceEncodingMatchesStat(t *testing.T) {
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("a C compiler is required to execute the BPF device encoding helper")
	}
	source, err := os.ReadFile("../../bpf/ransomware.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	declaration, body := cSourceFunction(t, string(source), "static __always_inline __u64 user_device_id(")
	program := `typedef unsigned int __u32;
typedef unsigned long long __u64;
#define __always_inline inline
` + declaration + " {" + body + "}\n" + `
int main(void) {
    const struct { __u32 major, minor; __u64 stat_device; } cases[] = {
        {0, 0, 0},
        {0, 255, 255},
        {8, 1, 0x801},
        {253, 0, 0xfd00},
        {259, 4096, 0x1010300},
        {4095, 1048575, 0xffffffffULL},
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        __u32 kernel_device = (cases[i].major << 20) | cases[i].minor;
        if (user_device_id(kernel_device) != cases[i].stat_device)
            return (int)i + 1;
    }
    return 0;
}
`
	binary := filepath.Join(t.TempDir(), "device-encoding")
	command := exec.Command(compiler, "-std=c11", "-Wall", "-Werror", "-x", "c", "-o", binary, "-")
	command.Stdin = strings.NewReader(program)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile production device helper: %v\n%s", err, output)
	}
	if output, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("production device encoding disagrees with stat major/minor fixtures: %v\n%s", err, output)
	}
}

func cSourceFunction(t *testing.T, source, marker string) (string, string) {
	t.Helper()
	start := strings.Index(source, marker)
	if start < 0 {
		t.Fatalf("missing C function %q", marker)
	}
	brace := strings.IndexByte(source[start:], '{')
	if brace < 0 {
		t.Fatalf("missing function body for %q", marker)
	}
	brace += start
	depth := 1
	for i := brace + 1; i < len(source); i++ {
		switch source[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return strings.TrimSpace(source[start:brace]), source[brace+1 : i]
			}
		}
	}
	t.Fatalf("unterminated function body for %q", marker)
	return "", ""
}
