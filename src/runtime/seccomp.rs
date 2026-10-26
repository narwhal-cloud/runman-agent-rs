//! Seccomp deny-list for instance processes (init and console sessions).
//!
//! Same scope as LXD's default for unprivileged containers: kernel module
//! loading, kexec and `open_by_handle_at` fail with EPERM. These already need
//! capabilities of the initial user namespace, so this is defense in depth
//! against kernel bugs on those paths. Compat ABIs are filtered by their own
//! syscall numbers (32-bit x86/ARM binaries, e.g. SteamCMD, keep working);
//! the x32 ABI, which practically nothing uses, is refused as a whole.
//! Everything else is allowed.

use std::io;

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const AUDIT_ARCH_I386: u32 = 0x4000_0003;
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
const AUDIT_ARCH_ARM: u32 = 0x4000_0028;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const RET_ALLOW: u32 = 0x7fff_0000;
const RET_EPERM: u32 = 0x0005_0000 | libc::EPERM as u32;

// kexec_load, kexec_file_load, init_module, finit_module, delete_module,
// open_by_handle_at (kexec_file_load does not exist on the 32-bit ABIs).
const X86_64: &[u32] = &[246, 320, 175, 313, 176, 304];
const I386: &[u32] = &[283, 128, 350, 129, 342];
const AARCH64: &[u32] = &[104, 294, 105, 273, 106, 265];
const ARM: &[u32] = &[347, 128, 379, 129, 371];

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_JSET_K: u16 = 0x45;
const BPF_RET_K: u16 = 0x06;
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Per-architecture block: load the syscall number, deny listed ones.
/// Always ends in a return, so the next arch test sees the arch value.
fn block(nrs: &[u32], deny_x32: bool) -> Vec<libc::sock_filter> {
    let mut b = vec![stmt(BPF_LD_W_ABS, OFF_NR)];
    let k = nrs.len() + usize::from(deny_x32);
    let mut i = 0;
    if deny_x32 {
        b.push(jump(BPF_JSET_K, X32_SYSCALL_BIT, (k - i) as u8, 0));
        i += 1;
    }
    for &nr in nrs {
        // Jump over the remaining tests and RET_ALLOW to RET_EPERM.
        b.push(jump(BPF_JEQ_K, nr, (k - i) as u8, 0));
        i += 1;
    }
    b.push(stmt(BPF_RET_K, RET_ALLOW));
    b.push(stmt(BPF_RET_K, RET_EPERM));
    b
}

pub fn program() -> Vec<libc::sock_filter> {
    let mut p = vec![stmt(BPF_LD_W_ABS, OFF_ARCH)];
    let arches: &[(u32, &[u32], bool)] = if cfg!(target_arch = "x86_64") {
        &[
            (AUDIT_ARCH_X86_64, X86_64, true),
            (AUDIT_ARCH_I386, I386, false),
        ]
    } else {
        &[
            (AUDIT_ARCH_AARCH64, AARCH64, false),
            (AUDIT_ARCH_ARM, ARM, false),
        ]
    };
    for &(arch, nrs, x32) in arches {
        let b = block(nrs, x32);
        p.push(jump(BPF_JEQ_K, arch, 0, b.len() as u8));
        p.extend(b);
    }
    p.push(stmt(BPF_RET_K, RET_ALLOW));
    p
}

/// Install the filter for this process and everything it executes.
/// Needs CAP_SYS_ADMIN in the current user namespace (container root has it),
/// so `no_new_privs` is not required and setuid programs keep working.
pub fn install() -> io::Result<()> {
    let mut filter = program();
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &prog as *const libc::sock_fprog,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_numbers_match_libc() {
        #[cfg(target_arch = "x86_64")]
        let native = X86_64;
        #[cfg(target_arch = "aarch64")]
        let native = AARCH64;
        let expected = [
            libc::SYS_kexec_load,
            libc::SYS_kexec_file_load,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_open_by_handle_at,
        ];
        let expected: Vec<u32> = expected.iter().map(|n| *n as u32).collect();
        assert_eq!(native, expected.as_slice());
    }

    /// Run the program in a tiny BPF interpreter.
    fn eval(arch: u32, nr: u32) -> u32 {
        let p = program();
        let mut acc = 0u32;
        let mut pc = 0usize;
        loop {
            let ins = p[pc];
            match ins.code {
                BPF_LD_W_ABS => acc = if ins.k == OFF_ARCH { arch } else { nr },
                BPF_JEQ_K => {
                    pc += usize::from(if acc == ins.k { ins.jt } else { ins.jf });
                }
                BPF_JSET_K => {
                    pc += usize::from(if acc & ins.k != 0 { ins.jt } else { ins.jf });
                }
                BPF_RET_K => return ins.k,
                other => panic!("unexpected opcode {other:#x}"),
            }
            pc += 1;
        }
    }

    #[test]
    fn filter_semantics() {
        let (native, compat, native_list, compat_list) = if cfg!(target_arch = "x86_64") {
            (AUDIT_ARCH_X86_64, AUDIT_ARCH_I386, X86_64, I386)
        } else {
            (AUDIT_ARCH_AARCH64, AUDIT_ARCH_ARM, AARCH64, ARM)
        };
        for &nr in native_list {
            assert_eq!(eval(native, nr), RET_EPERM, "native {nr}");
        }
        for &nr in compat_list {
            assert_eq!(eval(compat, nr), RET_EPERM, "compat {nr}");
        }
        for nr in [0, 1, 2, 59, 56, 435] {
            if !native_list.contains(&nr) {
                assert_eq!(eval(native, nr), RET_ALLOW, "native {nr}");
            }
            if !compat_list.contains(&nr) {
                assert_eq!(eval(compat, nr), RET_ALLOW, "compat {nr}");
            }
        }
        assert_eq!(eval(0x1234, 175), RET_ALLOW, "unknown arch is not filtered");
        if cfg!(target_arch = "x86_64") {
            assert_eq!(eval(native, X32_SYSCALL_BIT | 1), RET_EPERM, "x32 refused");
        }
    }
}
