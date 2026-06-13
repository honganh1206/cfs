#define _GNU_SOURCE

#include "security.h"

#include <errno.h>
#include <linux/capability.h>
#include <sched.h>
#include <seccomp.h>
#include <stdio.h>
#include <sys/capability.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>

#define SCMP_FAIL SCMP_ACT_ERRNO(EPERM)

int drop_capabilities(void) {
  fprintf(stderr, "=> dropping capabilities...");
  int drop_caps[] = {// Kernel audit system: configure/read/write audit logs.
                     CAP_AUDIT_CONTROL, CAP_AUDIT_READ, CAP_AUDIT_WRITE,
                     // Host power management: prevent suspend.
                     CAP_BLOCK_SUSPEND,
                     // Bypass file read and directory search permission checks.
                     CAP_DAC_READ_SEARCH,

                     // Preserve setuid/setgid bits when modifying files.
                     CAP_FSETID,

                     // Lock memory beyond normal limits.
                     CAP_IPC_LOCK,

                     // Mandatory Access Control administration/override powers.
                     CAP_MAC_ADMIN, CAP_MAC_OVERRIDE,

                     // Create device nodes.
                     CAP_MKNOD,

                     // Set file capabilities on executables.
                     CAP_SETFCAP,

                     // Privileged kernel log/syslog operations.
                     CAP_SYSLOG,

                     // Broad administrative power; heavily overloaded.
                     CAP_SYS_ADMIN,

                     // Reboot or related boot operations.
                     CAP_SYS_BOOT,

                     // Load/unload kernel modules.
                     CAP_SYS_MODULE,

                     // Raise scheduling priority / real-time scheduling powers.
                     CAP_SYS_NICE,

                     // Raw I/O and low-level device/memory access.
                     CAP_SYS_RAWIO,

                     // Override resource limits and quotas.
                     CAP_SYS_RESOURCE,

                     // Set system clock.
                     CAP_SYS_TIME,

                     // Wake system from suspend.
                     CAP_WAKE_ALARM};

  size_t num_caps = sizeof(drop_caps) / sizeof(*drop_caps);

  // Give bounding set
  fprintf(stderr, "bounding...");
  for (size_t i = 0; i < num_caps; i++) {
    if (prctl(PR_CAPBSET_DROP, drop_caps[i], 0, 0, 0)) {
      fprintf(stderr, "prctl failed: %m\n");
      return 1;
    }
  }

  // Give inheritable set
  fprintf(stderr, "inheritable...");
  // Set capabilities to child proc?
  cap_t caps = NULL;
  if (!(caps = cap_get_proc()) ||
      cap_set_flag(caps, CAP_INHERITABLE, num_caps, drop_caps, CAP_CLEAR) ||
      cap_set_proc(caps)) {
    fprintf(stderr, "failed: %m\n");
    if (caps)
      cap_free(caps);
    return 1;
  }
  cap_free(caps);
  fprintf(stderr, "done\n");
  return 0;
}

// Blacklist syscalls that lead to harms like sandbox escapes.
int install_seccomp_filter(void) {
  scmp_filter_ctx ctx = NULL;
  fprintf(stderr, "=> filtering syscalls...");
  // Seccomp system filter
  if (!(ctx = seccomp_init(SCMP_ACT_ALLOW))
      // Filter context, action on the dangerous syscall, syscall num, sycall
      // args
      // Prevent setuid/setgid
      // since a contained process without namespace could be used by any user
      // to get root
      || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,
                          SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) ||
      seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1,
                       SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) ||
      seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1,
                       SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) ||
      seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1,
                       SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) ||
      seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1,
                       SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) ||
      seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1,
                       SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) ||
      // Contained process can start new namespace and gain caps
      seccomp_rule_add(
          ctx, SCMP_FAIL, SCMP_SYS(unshare), 1,
          SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)) ||
      seccomp_rule_add(
          ctx, SCMP_FAIL, SCMP_SYS(clone), 1,
          SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER))
      // Contained process can write to controlling terminal
      || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ioctl), 1,
                          SCMP_A1(SCMP_CMP_MASKED_EQ, TIOCSTI, TIOCSTI)) ||
      // Kernel keyring system (store keys/tokens/certs in kernel memory)
      // isn't namespaced
      seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(keyctl), 0) ||
      seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(add_key), 0) ||
      seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(request_key), 0) ||
      // ptrace (Linux debugging/tracing mechanism) can modify what syscall
      // a process is about to make (before Linux 4.8 only?)
      // because it can write new values into CPU registers??
      seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ptrace), 0)
      // Prevent contained processes assign NUMA nodes (large servers have
      // non-unified memory access)
      // that can deny service to NUMA-aware application on the host
      || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(mbind), 0) ||
      seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(migrate_pages), 0) ||
      seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(move_pages), 0) ||
      seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(set_mempolicy), 0) ||
      // Pause execution in the kernel
      // by triggering page faults (memory mapped in virtual address but not
      // loaded to RAM) in system calls
      seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(userfaultfd), 0)
      // (Potentially) leak information on the host
      || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(perf_event_open), 0)
      // Do not automatically enable no_new_privs (safety switch to not gain
      // extra privileges) but some commands like ping needs this to send
      // network packets
      || seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0) || seccomp_load(ctx)) {
    if (ctx)
      seccomp_release(ctx);
    fprintf(stderr, "failed: %m\n");
    return 1;
  }
  seccomp_release(ctx);
  fprintf(stderr, "done\n");
  return 0;
}
