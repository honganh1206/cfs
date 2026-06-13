#ifndef CFS_CGROUPS_H
#define CFS_CGROUPS_H

#include <sys/types.h>

int setup_cgroup_v2(pid_t child_pid);
int cleanup_cgroup_v2(pid_t child_pid);

#endif
