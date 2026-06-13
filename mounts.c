#define _GNU_SOURCE

#include "mounts.h"

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

// Swap the mount at "/" with another
static int pivot_root(const char *new_root, const char *put_old) {
  return syscall(SYS_pivot_root, new_root, put_old);
}

// Child process in its own mount namespace, so we need to unmount things it
// should not have access to like the host's system tree
int setup_mounts(struct child_config *config) {
  fprintf(stderr, "=> remounting everything with MS_PRIVATE...");
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
    fprintf(stderr, "failed! %m\n");
    return -1;
  }
  fprintf(stderr, "remounted\n");

  // Bind-mount new root for child proc to rootfs passed in as arg
  // /tmp/tmp.XXXXXX -> /home/user/rootfs
  fprintf(stderr, "=> making a temp directory and a bind mount there...");
  // Host can see this dir, but it will be the contained process' root FS "/"
  char mount_dir[] = "/tmp/tmp.XXXXXX";
  if (!mkdtemp(mount_dir)) {
    fprintf(stderr, "failed making a directory\n");
    return -1;
  }
  if (mount(config->mount_dir, mount_dir, NULL, MS_BIND | MS_PRIVATE, NULL)) {
    fprintf(stderr, "bind mount failed\n");
  }

  char inner_mount_dir[] = "/tmp/tmp.XXXXXX/oldroot.XXXXXX";
  // Copy the host's FS to oldroot
  memcpy(inner_mount_dir, mount_dir, sizeof(mount_dir) - 1);
  if (!mkdtemp(inner_mount_dir)) {
    fprintf(stderr, "failed making the inner directory\n");
    return -1;
  }
  fprintf(stderr, "done\n");

  fprintf(stderr, "=> pivoting root...");
  if (pivot_root(mount_dir, inner_mount_dir)) {
    fprintf(stderr, "failed\n");
    return -1;
  }

  fprintf(stderr, "done\n");

  // Prepare to unmount the host FS (old root) and remove it
  char *old_root_dir = basename(inner_mount_dir);
  char old_root[sizeof(inner_mount_dir) + 1] = {"/"};
  strcpy(&old_root[1], old_root_dir);

  fprintf(stderr, "=> unmounting %s...", old_root);
  if (chdir("/")) {
    // Change PWD
    fprintf(stderr, "chdir failed %m\n");
    return -1;
  }
  if (umount2(old_root, MNT_DETACH)) {
    fprintf(stderr, "umount failed %m\n");
    return -1;
  }
  if (rmdir(old_root)) {
    return -1;
    fprintf(stderr, "rmdir failed %m\n");
  }
  fprintf(stderr, "done\n");
  return 0;
}
