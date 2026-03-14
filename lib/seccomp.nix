{ stdenv, lib, writeText, python3 }:

# Generate a seccomp BPF filter that blocks dangerous syscalls.
# The filter is a binary BPF program loadable via bwrap --seccomp FD.
#
# We use a Python script with ctypes to generate the raw BPF bytecode
# because libseccomp's nix package doesn't always expose the CLI tools.

let
  # Syscalls to BLOCK (return EPERM).
  # Everything not listed here is ALLOWED (deny-list approach).
  # This is conservative — blocks known-dangerous syscalls while
  # allowing everything a dev tool legitimately needs.
  blockedSyscalls = [
    # Filesystem namespace manipulation
    "mount"
    "umount2"
    "pivot_root"
    "chroot"

    # Process tracing (sandbox escape vector)
    "ptrace"
    "process_vm_readv"
    "process_vm_writev"

    # Kernel module loading
    "init_module"
    "finit_module"
    "delete_module"

    # System control
    "reboot"
    "kexec_load"
    "kexec_file_load"
    "swapon"
    "swapoff"
    "acct"

    # BPF and perf (kernel attack surface)
    "bpf"
    "perf_event_open"
    "userfaultfd"
    "lookup_dcookie"

    # Keyring manipulation
    "keyctl"
    "request_key"
    "add_key"

    # Time manipulation
    "settimeofday"
    "clock_settime"
    "adjtimex"
    "clock_adjtime"

    # Container escape vectors
    "open_by_handle_at"  # CVE-2015-1328
    "name_to_handle_at"

    # Deprecated / dangerous
    "nfsservctl"
    "personality"  # can change syscall ABI
    "kcmp"
  ];

  generateScript = writeText "gen-seccomp.py" ''
    #!/usr/bin/env python3
    """Generate a seccomp BPF filter in binary format for bwrap --seccomp."""
    import struct
    import sys
    import ctypes
    import ctypes.util

    # x86_64 syscall numbers
    # We hardcode these for x86_64; for aarch64 support, add a mapping.
    SYSCALL_MAP_X86_64 = {
        "mount": 165,
        "umount2": 166,
        "pivot_root": 155,
        "chroot": 161,
        "ptrace": 101,
        "process_vm_readv": 310,
        "process_vm_writev": 311,
        "init_module": 175,
        "finit_module": 313,
        "delete_module": 176,
        "reboot": 169,
        "kexec_load": 246,
        "kexec_file_load": 320,
        "swapon": 167,
        "swapoff": 168,
        "acct": 163,
        "bpf": 321,
        "perf_event_open": 298,
        "userfaultfd": 323,
        "lookup_dcookie": 212,
        "keyctl": 250,
        "request_key": 249,
        "add_key": 248,
        "settimeofday": 164,
        "clock_settime": 227,
        "adjtimex": 159,
        "clock_adjtime": 305,
        "open_by_handle_at": 304,
        "name_to_handle_at": 303,
        "nfsservctl": 180,
        "personality": 135,
        "kcmp": 312,
    }

    SYSCALL_MAP_AARCH64 = {
        "mount": 40,
        "umount2": 39,
        "pivot_root": 41,
        "chroot": 51,
        "ptrace": 117,
        "process_vm_readv": 270,
        "process_vm_writev": 271,
        "init_module": 105,
        "finit_module": 273,
        "delete_module": 106,
        "reboot": 142,
        "kexec_load": 104,
        "kexec_file_load": 294,
        "swapon": 224,
        "swapoff": 225,
        "acct": 89,
        "bpf": 280,
        "perf_event_open": 241,
        "userfaultfd": 282,
        "lookup_dcookie": 18,
        "keyctl": 219,
        "request_key": 218,
        "add_key": 217,
        "settimeofday": 170,
        "clock_settime": 112,
        "adjtimex": 171,
        "clock_adjtime": 266,
        "open_by_handle_at": 265,
        "name_to_handle_at": 264,
        "nfsservctl": 42,
        "personality": 92,
        "kcmp": 272,
    }

    import platform
    machine = platform.machine()
    if machine == "x86_64":
        AUDIT_ARCH = 0xC000003E  # AUDIT_ARCH_X86_64
        syscall_map = SYSCALL_MAP_X86_64
    elif machine == "aarch64":
        AUDIT_ARCH = 0xC00000B7  # AUDIT_ARCH_AARCH64
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
    BPF_K   = 0x00

    SECCOMP_RET_ALLOW = 0x7FFF0000
    SECCOMP_RET_ERRNO = 0x00050000
    EPERM = 1

    def bpf_stmt(code, k):
        return struct.pack("HBBI", code, 0, 0, k)

    def bpf_jump(code, k, jt, jf):
        return struct.pack("HBBI", code, jt, jf, k)

    blocked_syscalls = ${builtins.toJSON blockedSyscalls}
    blocked_nrs = []
    for name in blocked_syscalls:
        if name in syscall_map:
            blocked_nrs.append(syscall_map[name])

    # Build the BPF program
    instructions = []

    # Validate architecture
    # offsetof(struct seccomp_data, arch) = 4
    instructions.append(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 4))
    # If arch != expected, allow (don't break other arches)
    n_blocked = len(blocked_nrs)
    instructions.append(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0))
    instructions.append(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

    # Load syscall number
    # offsetof(struct seccomp_data, nr) = 0
    instructions.append(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0))

    # Check each blocked syscall
    for i, nr in enumerate(blocked_nrs):
        remaining = n_blocked - i - 1
        # If match: jump to DENY (which is at offset remaining + 1 from next instruction)
        # If no match: continue to next check (jf=0)
        instructions.append(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, remaining + 1, 0))

    # Default: ALLOW
    instructions.append(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

    # DENY: return EPERM
    instructions.append(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM))

    # Write raw BPF program
    program = b"".join(instructions)
    sys.stdout.buffer.write(program)
  '';

in
stdenv.mkDerivation {
  pname = "claude-sandbox-seccomp";
  version = "0.1.0";

  dontUnpack = true;

  nativeBuildInputs = [ python3 ];

  buildPhase = ''
    ${python3}/bin/python3 ${generateScript} > seccomp.bpf
  '';

  installPhase = ''
    mkdir -p $out
    cp seccomp.bpf $out/seccomp.bpf
  '';
}
