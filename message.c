#include <errno.h>
#include <fcntl.h>
#include "message.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "trace.h"
#include <unistd.h>
#include <zmq.h>

static void zmq_free_wrapper(void *data, void *hint)
{
	free(data);
}

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

static int reset_fd(int *fd)
{
	if (*fd == STDIN_FILENO || *fd == STDOUT_FILENO || *fd == STDERR_FILENO)
		return reset_std_fd(fd, (*fd == STDIN_FILENO) ? O_RDONLY : O_WRONLY);
	if (close(*fd))
		TRACE_ERRNO("close(%i) failed", *fd);
	*fd = -1;
	return 0;
}

int on_fd_readable(int *fd, void *socket, zmq_msg_t *msg, int *msg_valid, char msg_type)
{
	while (1) {
		if (*msg_valid)
			return 0;
		const size_t bufsize = 4096;
		char *buf = malloc(bufsize);
		if (buf == NULL) {
			TRACE("malloc(%zu) failed", bufsize);
			return -1;
		}
		buf[0] = msg_type;
		ssize_t count = read(*fd, buf + 1, bufsize - 1);
		if (count == -1) {
			if (errno == EAGAIN) {
				free(buf);
				return 0;
			}
			TRACE_ERRNO("read(%i, %p, %zu) failed", *fd, buf + 1, bufsize - 1);
			free(buf);
			return -1;
		}
		if (zmq_msg_init_data(msg, buf, count + 1, zmq_free_wrapper, NULL) == -1) {
			TRACE_ERRNO("zmq_msg_init_data() failed");
			free(buf);
			return -1;
		}
		*msg_valid = 1;
		if (socket_write(socket, msg, msg_valid) == -1)
			return -1;
		if (count == 0)
			return reset_fd(fd);
	}
}

int fd_write(int *fd, zmq_msg_t *msg, size_t *msg_pos)
{
	if (!*msg_pos)
		return 0;
	char *msg_data = zmq_msg_data(msg);
	size_t msg_size = zmq_msg_size(msg);
	if (msg_size == 1) {
		if (close(*fd) == -1)
			TRACE_ERRNO("close(%i) failed", *fd);
		*fd = -1;
	} else {
		while (*msg_pos != msg_size) {
			ssize_t count = write(*fd, msg_data + *msg_pos, msg_size - *msg_pos);
			if (count == -1) {
				if (errno == EAGAIN)
					return 0;
				TRACE_ERRNO("write(%i, %p, %zu) failed", *fd, msg_data + *msg_pos, msg_size - *msg_pos);
				return -1;
			}
			*msg_pos += count;
		}
	}
	if (zmq_msg_close(msg) == -1)
		TRACE_ERRNO("zmq_msg_close() failed");
	*msg_pos = 0;
	return 0;
}

int socket_write(void *socket, zmq_msg_t *msg, int *msg_valid)
{
	if (!*msg_valid)
		return 0;
	if (zmq_msg_send(msg, socket, ZMQ_DONTWAIT) == -1) {
		if (errno == EAGAIN)
			return 0;
		TRACE_ERRNO("zmq_msg_write() failed");
		return -1;
	}
	*msg_valid = 0;
	return 0;
}

