/* -*- compile-command: "gcc -Wall -Werror -lcap -lseccomp contained.c -o
 * contained" -*- */
/* This code is licensed under the GPLv3. You can find its text here:
   https://www.gnu.org/licenses/gpl-3.0.en.html */

#include <bits/getopt_core.h>
#include <signal.h>
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <pwd.h>
#include <sched.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct child_config {
  // Number of command-line args after -c
  int argc;
  // UNIX user ID
  uid_t uid;
  // File descriptor
  int fd;
  // Hostname to assign to the child environment
  char *hostname;
  // Array of command-line arguments
  // also pointer to the 1st argument after -c
  char **argv;
  // Path to dir used for mounting
  char *mount_dir;
};

// capabilities
// mounts
// syscalls
// resources
// child
int choose_hostname(char *buff, size_t len) {
  static const char *suits[] = {"swords", "wands", "pentacles", "cups"};
  static const char *minor[] = {"ace",  "two",    "three", "four", "five",
                                "six",  "seven",  "eight", "nine", "ten",
                                "page", "knight", "queen", "king"};
  static const char *major[] = {
      "fool",       "magician", "high-priestess", "empress",  "emperor",
      "hierophant", "lovers",   "chariot",        "strength", "hermit",
      "wheel",      "justice",  "hanged-man",     "death",    "temperance",
      "devil",      "tower",    "star",           "moon",     "sun",
      "judgment",   "world"};
  struct timespec now = {0};
  clock_gettime(CLOCK_MONOTONIC, &now);
  size_t ix = now.tv_nsec % 78;
  if (ix < sizeof(major) / sizeof(*major)) {
    snprintf(buff, len, "%05lx-%s", now.tv_sec, major[ix]);
  } else {
    ix -= sizeof(major) / sizeof(*major);
    snprintf(buff, len, "%05lxc-%s-of-%s", now.tv_sec,
             minor[ix % (sizeof(minor) / sizeof(*minor))],
             suits[ix / (sizeof(minor) / sizeof(*minor))]);
  }
  return 0;
}

// ./contained -m /tmp/rootfs -u 1000 -c /bin/sh
int main(int argc, char **argv) {
  struct child_config config = {0};
  int err = 0;
  int option = 0;
  int sockets[2] = {0};
  pid_t child_pid = 0;
  int last_optind = 0;

  // Parse command-line options
  while ((option = getopt(argc, argv, "c:m:u"))) {
    switch (option) {
    case 'c':
      // Calculate number of args
      config.argc = argc - last_optind - 1;
      config.argv = &argv[argc - config.argc];
      // Jump straight to this position
      goto finish_options;
    case 'm':
      // Set mount_dir only?
      config.mount_dir = optarg;
      break;
    case 'u':
      if (sscanf(optarg, "%d", &config.uid) != 1) {
        fprintf(stderr, "badly-formatted uid: %s\n", optarg);
        goto usage;
      }
      break;
    default:
      break;
    }
    // Get index of the next argv to be scanned
    last_optind = optind;
  }
finish_options:
  if (!config.argc)
    goto usage;
  if (!config.mount_dir)
    goto usage;

  // check-linux-version
  fprintf(stderr, "=> validating Linux version...");
  // Store system and kernel info from using uname()
  struct utsname host = {0};
  if (uname(&host)) {
    fprintf(stderr, "failed: %m\n");
    goto cleanup;
  }
  int major = -1;
  int minor = -1;
  if (sscanf(host.release, "%u.%u", &major, &minor) != 2) {
    fprintf(stderr, "weird release format: %s\n", host.release);
    goto cleanup;
  }
  // Why this specific version?
  if (major != 4 || (minor != 7 && minor != 8)) {
    fprintf(stderr, "expected 4.7.x or 4.8.x: %s\n", host.release);
    goto cleanup;
  }
  if (strcmp("x86_64", host.machine)) {
    fprintf(stderr, "expected x886_64: %s\n", host.machine);
    goto cleanup;
  }
  fprintf(stderr, "%s on %s.\n", host.release, host.machine);

  char hostname[256] = {0};
  if (choose_hostname(hostname, sizeof(hostname)))
    // What could go wrong here?
    goto error;
  config.hostname = hostname;
  // namespaces
  // We use clone syscall to create a process with different props compared to
  // the parent one, meaning mount a different /, set its own hostname, etc.
  // Communicate with parent process via socketpair (data written to one socket
  // can be read from the other)
  if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets)) {
    // Local socket, packet-like messages
    fprintf(stderr, "socketpair failed: %m\n");
    goto error;
  }
  if (fcntl(sockets[0], F_SETFD, FD_CLOEXEC)) {
    // When parent calls exec(), automatically close sockets[0]
    // since we do not want child to inherit parent's fd
    fprintf(stderr, "fcntl failed: %m\n");
    goto error;
  }
  config.fd = sockets[1];
// Prepare cgroup (dedicated CPU & RAM)
#define STACK_SIZE (1024 * 1024)
  char *stack = 0;
  if (!(stack = malloc(STACK_SIZE))) {
    fprintf(stderr, "=> malloc failed, out of memory?\n");
    goto error;
  }
  if (resources(&config)) {
    err = 1;
    goto clear_resources;
  }
  int flags = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWPID | CLONE_NEWIPC |
              CLONE_NEWNET | CLONE_NEWUTS;

  // Child process starts the child() function
  // and the stack moves downward (high -> low address)
  // and parent process waits to collect child's exit status
  if ((child_pid =
           clone(child, stack + STACK_SIZE, flags | SIGCHLD, &config)) == -1) {
    fprintf(stderr, "=> clone failed! %m\n");
    err = 1;
    goto clear_resources;
  }
  // Close child's socket so we don't leave an open fd
  close(sockets[1]);
  sockets[1] = 0;
  goto cleanup;
usage:
  fprintf(stderr, "Usage: %s -u -l -m . /bin/sh ~\n", argv[0]);
error:
  // Mark program as failed
  err = 1;
cleanup:
  if (sockets[0])
    close(sockets[0]);
  if (sockets[1])
    close(sockets[1]);
  return err;
}
