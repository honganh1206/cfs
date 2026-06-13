#include "cgroups.h"

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Helper function to DRY open()/write()
static int write_file(const char *path, const char *value) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);

  if (fd == -1) {
    fprintf(stderr, "open %s failed: %m\n", path);
    return -1;
  }

  ssize_t len = (ssize_t)strlen(value);

  if (write(fd, value, len) != len) {
    fprintf(stderr, "write %s failed: %m\n", path);
    close(fd);
    return -1;
  }

  close(fd);
  return 0;
}

int setup_cgroup_v2(pid_t child_pid) {
  char cgroup_dir[PATH_MAX];
  char path[PATH_MAX];
  char pidbuf[32];

  fprintf(stderr, "=> setting cgroup v2 limits...");

  snprintf(cgroup_dir, sizeof(cgroup_dir), "/sys/fs/cgroup/contained-%d",
           child_pid);

  if (mkdir(cgroup_dir, 0700) == -1 && errno != EEXIST) {
    fprintf(stderr, "mkdir %s failed: %m\n", cgroup_dir);
    return -1;
  }

  if (snprintf(path, sizeof(path), "%s/memory.max", cgroup_dir) == -1)
    return -1;

  if (write_file(path, MEMORY) == -1)
    return -1;

  if (snprintf(path, sizeof(path), "%s/pids.max", cgroup_dir) == -1)
    return -1;

  if (write_file(path, PIDS) == -1)
    return -1;

  if (snprintf(path, sizeof(path), "%s/cpu.weight", cgroup_dir) == -1)
    return -1;
  if (write_file(path, SHARES) == -1)
    return -1;

  if (snprintf(pidbuf, sizeof(pidbuf), "%d", child_pid) == -1)
    return -1;

  if (snprintf(path, sizeof(path), "%s/cgroup.procs", cgroup_dir) == -1)
    return -1;
  if (write_file(path, pidbuf) == -1)
    return -1;

  fprintf(stderr, "done.\n");

  return 0;
}

int cleanup_cgroup_v2(pid_t child_pid) {
  char cgroup_dir[PATH_MAX];

  fprintf(stderr, "=> cleaning cgroup v2...");

  if (snprintf(cgroup_dir, sizeof(cgroup_dir), "/sys/fs/cgroup/contained-%d",
               child_pid) == -1)
    return -1;

  if (rmdir(cgroup_dir) == -1) {
    fprintf(stderr, "rmdir %s failed: %m\n", cgroup_dir);
    return -1;
  }

  fprintf(stderr, "done.\n");
  return 0;
}
