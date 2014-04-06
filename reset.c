#include <fcntl.h>
#include "reset.h"
#include <sys/stat.h>
#include <sys/types.h>
#include "trace.h"
#include <unistd.h>

static int reset_std_fd(int *fd, int flags)
{
	int rc = -1;

	int null_fd = open("/dev/null", flags);
	if (null_fd == -1) {
		TRACE_ERRNO("open() failed");
		goto _out;
	}

	if (dup2(null_fd, *fd) == -1) {
		TRACE_ERRNO("dup2(%i, %i) failed", null_fd, *fd);
		goto _out_close_null_fd;
	}

	*fd = -1;
	rc = 0;

_out_close_null_fd:
	if (close(null_fd) == -1)
		TRACE_ERRNO("close(%i) failed", null_fd);

_out:
	return rc;
}

int reset_fd(int *fd)
{
	if (*fd == -1)
		return 0;
	if (*fd == STDIN_FILENO || *fd == STDOUT_FILENO || *fd == STDERR_FILENO)
		return reset_std_fd(fd, (*fd == STDIN_FILENO) ? O_RDONLY : O_WRONLY);
	if (close(*fd))
		TRACE_ERRNO("close(%i) failed", *fd);
	*fd = -1;
	return 0;
}
