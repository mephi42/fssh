#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "trace.h"
#include "un.h"

void un_initaddr(struct sockaddr_un *sa, const char *guid)
{
	sa->sun_family = AF_UNIX;
	snprintf(sa->sun_path, sizeof(sa->sun_path), "/tmp/fssh-%s", guid);
}

int un_listen(const struct sockaddr_un *sa)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		TRACE_ERRNO("socket() failed");
		goto _fail_socket;
	}

	if (bind(fd, (const struct sockaddr *)sa, sizeof(*sa)) == -1) {
		TRACE_ERRNO("bind(%d, %s) failed", fd, sa->sun_path);
		goto _fail_bind;
	}

	if (listen(fd, 1) == -1) {
		TRACE_ERRNO("listen(%d) failed", fd);
		goto _fail_listen;
	}

	return fd;

_fail_listen:
	if (unlink(sa->sun_path) == -1)
		TRACE_ERRNO("unlink(%s) failed", sa->sun_path);
_fail_bind:
	if (close(fd) == -1)
		TRACE_ERRNO("close(%d) failed", fd);
_fail_socket:
	return -1;
}
