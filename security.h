#ifndef CFS_SECURITY_H
#define CFS_SECURITY_H

int drop_capabilities(void);
int install_seccomp_filter(void);

#endif
