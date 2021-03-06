#include "anyzmq.h"
#include <errno.h>
#include <fcntl.h>
#include "message.h"
#include "reset.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "trace.h"
#include <unistd.h>

int get_msg_hdr(zmq_msg_t *msg)
{
	char *data = zmq_msg_data(msg);
	char hdr = data[0];
	return hdr & 0xff;
}

static void zmq_free_wrapper(void *data, void *hint)
{
	(void)hint;
	free(data);
}

int on_fd_readable(int *fd, void *socket, zmq_msg_t *msg, int *msg_valid, char msg_type, int *msg_seq)
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
		buf[0] = MSG_HDR(msg_type, *msg_seq);
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
		TRACE("read data for message, type=%i, size=%zd", (int)msg_type, count);
		if (zmq_msg_init_data(msg, buf, count + 1, zmq_free_wrapper, NULL) == -1) {
			TRACE_ERRNO("zmq_msg_init_data() failed");
			free(buf);
			return -1;
		}
		*msg_valid = 1;
		++(*msg_seq);
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
	size_t msg_size = zmq_msg_size(msg);
	char *msg_data = zmq_msg_data(msg);
	if (msg_size == 1) {
		if (reset_fd(fd) == -1)
			return -1;
		int msg_hdr = get_msg_hdr(msg);
		TRACE("closed stream, type=%i, seq=%i", MSG_HDR_TYPE(msg_hdr), MSG_HDR_SEQ(msg_hdr));
	} else {
		while (*msg_pos != msg_size) {
			ssize_t count = write(*fd, msg_data + *msg_pos, msg_size - *msg_pos);
			if (count == -1) {
				if (errno == EAGAIN)
					return 0;
				TRACE_ERRNO("write(%i, %p, %zu) failed", *fd, msg_data + *msg_pos, msg_size - *msg_pos);
				return -1;
			}
			int msg_hdr = get_msg_hdr(msg);
			TRACE("wrote data from message, type=%i, seq=%i, size=%zd", MSG_HDR_TYPE(msg_hdr), MSG_HDR_SEQ(msg_hdr), count);
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
	int msg_hdr = get_msg_hdr(msg);
	int msg_type = MSG_HDR_TYPE(msg_hdr);
	int msg_seq = MSG_HDR_SEQ(msg_hdr);
	size_t msg_size = zmq_msg_size(msg);
	if (zmq_msg_send(msg, socket, ZMQ_DONTWAIT) == -1) {
		if (errno == EAGAIN)
			return 0;
		TRACE_ERRNO("zmq_msg_send(%p) failed", socket);
		return -1;
	}
	TRACE("sent message, type=%i, seq=%i, size=%zu", msg_type, msg_seq, msg_size);
	*msg_valid = 0;
	return 0;
}

