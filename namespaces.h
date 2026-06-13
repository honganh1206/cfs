#ifndef CFS_NAMESPACES_H
#define CFS_NAMESPACES_H

#include "config.h"

#include <sys/types.h>

int configure_child_userns(pid_t child_pid, int fd);
int enter_user_namespace(struct child_config *config);

#endif
