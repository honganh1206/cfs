#define _GNU_SOURCE

#include "namespaces.h"

#include <fcntl.h>
#include <grp.h>
#include <linux/limits.h>
#include <sched.h>
#include <stdio.h>
#include <unistd.h>

// Parent process configures the child user's namespace (userns)
int configure_child_userns(pid_t child_pid, int fd) {
  int uid_map = 0;
  int has_userns = -1;
  // Read from the child proc whether it created/uses a user namespace
  if (read(fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
    fprintf(stderr, "couldn't read from child!\n");
    return -1;
  }
  // If non-zero then parent must writes UID/GID maps
  if (has_userns) {
    char path[PATH_MAX] = {0};
    // Loop over two proc files and write to both
    for (char **file = (char *[]){"uid_map", "gid_map", 0}; *file; file++) {
      if (snprintf(path, sizeof(path), "/proc/%d/%s", child_pid, *file) >
          sizeof(path)) {
        fprintf(stderr, "snprintf too big? %m\n");
        return -1;
      }
      fprintf(stderr, "=> writing %s...", path);
      // Open UID/GID maps to write
      if ((uid_map = open(path, O_WRONLY)) == -1) {
        fprintf(stderr, "open failed: %m\n");
        return -1;
      }
      // Write inside namespace UID/GID to outside namespace UID/GID 10000
      if (dprintf(uid_map, "0 %d %d\n", USERNS_OFFSET, USERNS_COUNT) == -1) {
        // something like 0 100000 65536
        fprintf(stderr, "dprintf failed: %m\n");
        close(uid_map);
        return -1;
      }
      close(uid_map);
    }
  }
  // Writing done, child can continue
  // since child is probably blocked by parent writing to maps
  if (write(fd, &(int){0}, sizeof(int)) != sizeof(int)) {
    fprintf(stderr, "couldn't write: %m\n");
    return -1;
  }
  return 0;
}

// Enter a new user namespace (running in child process).
// After the parent process is done writing UID/GID maps,
// switch the child process to the requested UID/GID.
int enter_user_namespace(struct child_config *config) {
  fprintf(stderr, "=> trying a user namespace...");
  // Disassociate parts of the execution context (like namespaces)
  // of child process from parent process
  int has_userns = !unshare(CLONE_NEWUSER);
  if (write(config->fd, &has_userns, sizeof(has_userns)) !=
      sizeof(has_userns)) {
    fprintf(stderr, "couldn't write: %m\n");
    return -1;
  }
  int result = 0;
  if (read(config->fd, &result, sizeof(result)) != sizeof(result)) {
    fprintf(stderr, "couldn't read: %m\n");
    return -1;
  }
  if (result)
    return -1;
  if (has_userns) {
    fprintf(stderr, "done.\n");
  } else {
    fprintf(stderr, "unsupported? continuing.\n");
  }
  fprintf(stderr, "=> switching to uid %d / gid %d...", config->uid,
          config->uid);
  if (setgroups(1, &(gid_t){config->uid}) ||
      setresgid(config->uid, config->uid, config->uid) ||
      setresuid(config->uid, config->uid, config->uid)) {
    // Save real user ID? effective group ID? saved-set ID?
    fprintf(stderr, "%m\n");
    return -1;
  }
  fprintf(stderr, "done.\n");
  return 0;
}
