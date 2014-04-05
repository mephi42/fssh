#include <fcntl.h>

#include "nonblock.h"
#include "trace.h"

int make_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		TRACE_ERRNO("fcntl(%d, F_GETFL) failed", fd);
		return -1;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		TRACE_ERRNO("fcntl(%d, F_SETFL) failed", fd);
		return -1;
	}
	return 0;
}
