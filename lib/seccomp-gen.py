#!/usr/bin/env python3
"""Generate a seccomp BPF filter in binary format for bwrap --seccomp.

Usage:
    seccomp-gen.py [EXTRA_SYSCALL ...]
    seccomp-gen.py --list

Outputs raw BPF bytecode to stdout. Extra syscall names passed as arguments
are added to the default blocked list.
"""
import struct
import sys
import platform

# ── Default blocked syscalls ─────────────────────────────────────────
# Everything NOT listed here is ALLOWED (deny-list approach).
DEFAULT_BLOCKED = [
    # Filesystem namespace manipulation
    "mount",
    "umount2",
    "pivot_root",
    "chroot",
    # Process tracing (sandbox escape vector)
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    # Kernel module loading
    "init_module",
    "finit_module",
    "delete_module",
    # System control
    "reboot",
    "kexec_load",
    "kexec_file_load",
    "swapon",
    "swapoff",
    "acct",
    # BPF and perf (kernel attack surface)
    "bpf",
    "perf_event_open",
    "userfaultfd",
    "lookup_dcookie",
    # Keyring manipulation
    "keyctl",
    "request_key",
    "add_key",
    # Time manipulation
    "settimeofday",
    "clock_settime",
    "adjtimex",
    "clock_adjtime",
    # Container escape vectors
    "open_by_handle_at",
    "name_to_handle_at",
    # io_uring — massive kernel attack surface, numerous privesc CVEs
    # (CVE-2021-41073, CVE-2022-29582, CVE-2023-2598, CVE-2024-0582)
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    # Namespace manipulation — prevent nested namespace creation/escape
    "unshare",
    "setns",
    # Seccomp self-modification — prevent BPF verifier exploitation
    "seccomp",
    # Deprecated / dangerous
    "nfsservctl",
    "personality",
    "kcmp",
]

# ── Syscall number tables ────────────────────────────────────────────
SYSCALL_MAP_X86_64 = {
    "mount": 165, "umount2": 166, "pivot_root": 155, "chroot": 161,
    "ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311,
    "init_module": 175, "finit_module": 313, "delete_module": 176,
    "reboot": 169, "kexec_load": 246, "kexec_file_load": 320,
    "swapon": 167, "swapoff": 168, "acct": 163,
    "bpf": 321, "perf_event_open": 298, "userfaultfd": 323, "lookup_dcookie": 212,
    "keyctl": 250, "request_key": 249, "add_key": 248,
    "settimeofday": 164, "clock_settime": 227, "adjtimex": 159, "clock_adjtime": 305,
    "open_by_handle_at": 304, "name_to_handle_at": 303,
    "nfsservctl": 180, "personality": 135, "kcmp": 312,
    # Extra syscalls that users may want to block
    "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
    "socket": 41, "connect": 42, "accept": 43, "accept4": 288,
    "sendto": 44, "recvfrom": 45, "sendmsg": 46, "recvmsg": 47,
    "bind": 49, "listen": 50, "getsockname": 51, "getpeername": 52,
    "socketpair": 53, "setsockopt": 54, "getsockopt": 55, "shutdown": 48,
    "clone": 56, "clone3": 435, "unshare": 272, "setns": 308,
    "execve": 59, "execveat": 322,
    "mknod": 133, "mknodat": 259,
    "ioctl": 16,
    "prctl": 157,
    "seccomp": 317,
    "memfd_create": 319,
    "flock": 73,
}

SYSCALL_MAP_AARCH64 = {
    "mount": 40, "umount2": 39, "pivot_root": 41, "chroot": 51,
    "ptrace": 117, "process_vm_readv": 270, "process_vm_writev": 271,
    "init_module": 105, "finit_module": 273, "delete_module": 106,
    "reboot": 142, "kexec_load": 104, "kexec_file_load": 294,
    "swapon": 224, "swapoff": 225, "acct": 89,
    "bpf": 280, "perf_event_open": 241, "userfaultfd": 282, "lookup_dcookie": 18,
    "keyctl": 219, "request_key": 218, "add_key": 217,
    "settimeofday": 170, "clock_settime": 112, "adjtimex": 171, "clock_adjtime": 266,
    "open_by_handle_at": 265, "name_to_handle_at": 264,
    "nfsservctl": 42, "personality": 92, "kcmp": 272,
    # Extra syscalls that users may want to block
    "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
    "socket": 198, "connect": 203, "accept": 202, "accept4": 242,
    "sendto": 206, "recvfrom": 207, "sendmsg": 211, "recvmsg": 212,
    "bind": 200, "listen": 201, "getsockname": 204, "getpeername": 205,
    "socketpair": 199, "setsockopt": 208, "getsockopt": 209, "shutdown": 210,
    "clone": 220, "clone3": 435, "unshare": 97, "setns": 268,
    "execve": 221, "execveat": 281,
    "mknod": 33, "mknodat": 33,
    "ioctl": 29,
    "prctl": 167,
    "seccomp": 277,
    "memfd_create": 279,
    "flock": 32,
}


def generate_bpf(blocked_names):
    """Generate raw BPF bytecode blocking the given syscalls."""
    machine = platform.machine()
    if machine == "x86_64":
        AUDIT_ARCH = 0xC000003E
        syscall_map = SYSCALL_MAP_X86_64
    elif machine == "aarch64":
        AUDIT_ARCH = 0xC00000B7
        syscall_map = SYSCALL_MAP_AARCH64
    else:
        print(f"Unsupported architecture: {machine}", file=sys.stderr)
        sys.exit(1)

    # BPF constants
    BPF_LD  = 0x00
    BPF_JMP = 0x05
    BPF_RET = 0x06
    BPF_W   = 0x00
    BPF_ABS = 0x20
    BPF_JEQ = 0x10
    BPF_JGE = 0x30
    BPF_K   = 0x00

    SECCOMP_RET_ALLOW = 0x7FFF0000
    SECCOMP_RET_ERRNO = 0x00050000
    SECCOMP_RET_KILL_PROCESS = 0x80000000
    EPERM = 1
    X32_SYSCALL_BIT = 0x40000000

    def bpf_stmt(code, k):
        return struct.pack("HBBI", code, 0, 0, k)

    def bpf_jump(code, k, jt, jf):
        return struct.pack("HBBI", code, jt, jf, k)

    # Resolve syscall names to numbers
    blocked_nrs = []
    unknown = []
    for name in blocked_names:
        if name in syscall_map:
            blocked_nrs.append(syscall_map[name])
        else:
            unknown.append(name)
    if unknown:
        print(f"Warning: unknown syscalls (skipped): {', '.join(unknown)}", file=sys.stderr)

    # Deduplicate
    blocked_nrs = sorted(set(blocked_nrs))
    n_blocked = len(blocked_nrs)

    # Build BPF program
    instructions = []

    # Step 1: Validate architecture
    instructions.append(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 4))
    instructions.append(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0))
    instructions.append(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS))

    # Step 2: Load syscall number
    instructions.append(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0))

    # Step 3 (x86_64 only): Block x32 ABI syscalls
    if machine == "x86_64":
        instructions.append(bpf_jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, n_blocked + 1, 0))

    # Step 4: Check each blocked syscall
    for i, nr in enumerate(blocked_nrs):
        remaining = n_blocked - i - 1
        instructions.append(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, remaining + 1, 0))

    # Step 5: Default ALLOW
    instructions.append(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

    # Step 6: DENY — return EPERM
    instructions.append(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM))

    return b"".join(instructions)


if __name__ == "__main__":
    if "--list" in sys.argv:
        machine = platform.machine()
        smap = SYSCALL_MAP_X86_64 if machine == "x86_64" else SYSCALL_MAP_AARCH64
        print("Available syscall names:")
        for name in sorted(smap.keys()):
            marker = " [blocked by default]" if name in DEFAULT_BLOCKED else ""
            print(f"  {name}{marker}")
        sys.exit(0)

    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__.strip())
        sys.exit(0)

    extra = [a for a in sys.argv[1:] if not a.startswith("-")]
    all_blocked = list(dict.fromkeys(DEFAULT_BLOCKED + extra))  # deduplicate, preserve order

    program = generate_bpf(all_blocked)
    sys.stdout.buffer.write(program)
