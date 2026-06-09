#!/usr/bin/env python3
import argparse
import os
import time


def fanout(base, count, delay):
    os.makedirs(base, exist_ok=True)
    for i in range(count):
        path = os.path.join(base, f"fanout-{i}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"data-{i}\n")
        time.sleep(delay)


def rename_suffix(base, count, delay, suffix):
    os.makedirs(base, exist_ok=True)
    for i in range(count):
        path = os.path.join(base, f"doc-{i}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"data-{i}\n")
        os.rename(path, path + suffix)
        time.sleep(delay)


def ransom_note(base, count, delay, note_name):
    os.makedirs(base, exist_ok=True)
    for i in range(count):
        path = os.path.join(base, f"note-stage-{i}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"data-{i}\n")
        time.sleep(delay)
    with open(os.path.join(base, note_name), "w", encoding="utf-8") as f:
        f.write("send payment to recover files\n")


def main():
    parser = argparse.ArgumentParser(description="Small ransomware-like workload simulator for ebpffls integration tests.")
    parser.add_argument("--mode", choices=("fanout", "rename-suffix", "ransom-note"), required=True)
    parser.add_argument("--dir", required=True)
    parser.add_argument("--count", type=int, default=64)
    parser.add_argument("--delay", type=float, default=0.02)
    parser.add_argument("--suffix", default=".locked")
    parser.add_argument("--note-name", default="README_FOR_DECRYPT.txt")
    args = parser.parse_args()

    if args.mode == "fanout":
        fanout(args.dir, args.count, args.delay)
    elif args.mode == "rename-suffix":
        rename_suffix(args.dir, args.count, args.delay, args.suffix)
    elif args.mode == "ransom-note":
        ransom_note(args.dir, args.count, args.delay, args.note_name)

    time.sleep(5)
    print("survived")


if __name__ == "__main__":
    main()
