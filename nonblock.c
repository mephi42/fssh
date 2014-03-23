#include <fcntl.h>

#include "nonblock.h"
#include "trace.h"

int make_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFD);
	if (flags == -1) {
		TRACE_ERRNO("fcntl(%d, F_GETFD) failed", fd);
		return -1;
	}
	if (fcntl(fd, F_SETFD, flags | O_NONBLOCK) == -1) {
		TRACE_ERRNO("fcntl(%d, F_SETFD) failed", fd);
		return -1;
	}
	return 0;
}
