#include "child.h"

#include "config.h"
#include "mounts.h"
#include "namespaces.h"
#include "security.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Entry point for the cloned child process
int child(void *arg) {
  struct child_config *config = arg;
  // NOTE: The order is important.
  // We perform setup, switch user and group, load the executables
  if (sethostname(config->hostname, strlen(config->hostname)) ||
      setup_mounts(config) || enter_user_namespace(config) ||
      drop_capabilities() || install_seccomp_filter()) {
    close(config->fd);
    return -1;
  }
  if (close(config->fd)) {
    fprintf(stderr, "close failed: %m\n");
    return -1;
  }
  // Replace the current process with /bin/sh?
  // and pass the argv and envp to it
  if (execve(config->argv[0], config->argv, NULL)) {
    fprintf(stderr, "execve failed! %m\n");
    return -1;
  }
  return 0;
}
