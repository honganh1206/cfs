#ifndef CFS_CONFIG_H
#define CFS_CONFIG_H

#include <sys/types.h>

#define STACK_SIZE (1024 * 1024)
#define USERNS_OFFSET 10000
#define USERNS_COUNT 2000

// No more than 1GB in userspace
#define MEMORY "104857600"
// A quarter of CPU time on a busy system at most
#define SHARES "25"
// Contained process has 64 PIDs at most
#define PIDS "64"

struct child_config {
  // Number of command-line args after -c
  int argc;
  // UNIX user ID
  uid_t uid;
  // File descriptor
  int fd;
  // Hostname to assign to the child environment
  char *hostname;
  // Array of command-line arguments, also pointer to the first argument after -c
  char **argv;
  // Path to dir used for mounting
  char *mount_dir;
};

#endif
