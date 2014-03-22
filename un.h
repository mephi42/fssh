#ifndef FSSH_UN_H
#define FSSH_UN_H

#include <sys/un.h>

void un_initaddr(struct sockaddr_un *sa, const char *guid);
int un_listen(const struct sockaddr_un *sa);

#endif
