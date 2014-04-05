#include <arpa/inet.h>
#include "message.h"
#include "nonblock.h"
#include <stdio.h>
#include <stdint.h>
#include "trace.h"
#include <unistd.h>
#include <zmq.h>

static int on_socket_readable(void *socket, int *stdout_fd, int *stderr_fd, zmq_msg_t *msg, size_t *msg_pos, int *exited, int *code)
{
	while (1) {
		if (*msg_pos)
			return 0;
		if (zmq_msg_init(msg) == -1) {
			TRACE("zmq_msg_init() failed");
			return -1;
		}
		if (zmq_msg_recv(msg, socket, ZMQ_DONTWAIT) == -1) {
			if (errno == EAGAIN)
				return 0;
			TRACE_ERRNO("zmq_msg_recv() failed");
			return -1;
		}
		size_t msg_size = zmq_msg_size(msg);
		if (msg_size == 0) {
			TRACE("empty message received");
			return -1;
		}
		char *msg_data = zmq_msg_data(msg);
		char msg_type = msg_data[0];
		TRACE("received message, type=%i, size=%zu", (int)msg_type, msg_size);
		switch (msg_type) {
		case msg_type_stdout:
			*msg_pos = 1;
			if (fd_write(stdout_fd, msg, msg_pos) == -1)
				return -1;
			break;
		case msg_type_stderr:
			*msg_pos = 1;
			if (fd_write(stderr_fd, msg, msg_pos) == -1)
				return -1;
			break;
		case msg_type_exit:
			if (msg_size != 5) {
				TRACE("exit message with unexpected length received");
				return -1;
			}
			*exited = 1;
			*code = (int)ntohl(*(uint32_t*)&msg_data[1]);
			TRACE("this is exit message, code=%i", *code);
			if (zmq_msg_close(msg) == -1)
				TRACE("zmq_msg_close() failed");
			*msg_pos = 0;
			return 0;
		default:
			TRACE("message with unexpected type received");
			return -1;
		}
	}
}

static int forward(int *stdin_fd, int *stdout_fd, int *stderr_fd, void *socket, int *code)
{
	int rc = -1;

	zmq_msg_t stdin_msg;
	int stdin_msg_valid = 0;
	zmq_msg_t stdouterr_msg;
	size_t stdouterr_msg_pos = 0;

	if (make_nonblocking(*stdin_fd) == -1)
		goto _out;
	if (make_nonblocking(*stdout_fd) == -1)
		goto _out;
	if (make_nonblocking(*stderr_fd) == -1)
		goto _out;

	while (1) {
		zmq_pollitem_t items[4];
		zmq_pollitem_t *item = items;

		zmq_pollitem_t *stdin_item = NULL;
		if (*stdin_fd != -1 && !stdin_msg_valid) {
			stdin_item = item++;
			stdin_item->socket = NULL;
			stdin_item->fd = *stdin_fd;
			stdin_item->events = ZMQ_POLLIN | ZMQ_POLLERR;
		}

		zmq_pollitem_t *stdout_item = NULL;
		if (*stdout_fd != -1 && stdouterr_msg_pos && ((char*)zmq_msg_data(&stdouterr_msg))[0] == msg_type_stdout) {
			stdout_item = item++;
			stdout_item->socket = NULL;
			stdout_item->fd = *stdout_fd;
			stdout_item->events = ZMQ_POLLOUT | ZMQ_POLLERR;
		}

		zmq_pollitem_t *stderr_item = NULL;
		if (*stderr_fd != -1 && stdouterr_msg_pos && ((char*)zmq_msg_data(&stdouterr_msg))[0] == msg_type_stderr) {
			stderr_item = item++;
			stderr_item->socket = NULL;
			stderr_item->fd = *stderr_fd;
			stderr_item->events = ZMQ_POLLOUT | ZMQ_POLLERR;
		}

		zmq_pollitem_t *socket_item = NULL;
		short socket_events = (stdin_msg_valid ? ZMQ_POLLOUT : 0) |
		                      (stdouterr_msg_pos ? 0 : ZMQ_POLLIN);
		if (socket_events) {
			socket_item = item++;
			socket_item->socket = socket;
			socket_item->fd = -1;
			socket_item->events = socket_events;
		}

		if (item == items) {
			TRACE("nothing to poll, exiting");
			break;
		}

		TRACE("polling:%s%s%s%s", stdin_item ? " stdin" : "",
		                          stdout_item ? " stdout" : "",
		                          stderr_item ? " stderr" : "",
		                          socket_item ? " socket" : "");

		while (1) {
			if (zmq_poll(items, item - items, -1) == -1) {
				if (errno == EINTR)
					continue;
				TRACE_ERRNO("zmq_poll() failed");
				goto _out;
			}
			break;
		}

		if (stdout_item && (stdout_item->revents & (ZMQ_POLLOUT | ZMQ_POLLERR)))
			if (fd_write(stdout_fd, &stdouterr_msg, &stdouterr_msg_pos) == -1)
				goto _out;
		if (stderr_item && (stderr_item->revents & (ZMQ_POLLOUT | ZMQ_POLLERR)))
			if (fd_write(stderr_fd, &stdouterr_msg, &stdouterr_msg_pos) == -1)
				goto _out;
		if (socket_item && (socket_item->revents & ZMQ_POLLOUT))
			if (socket_write(socket, &stdin_msg, &stdin_msg_valid) == -1)
				goto _out;
		if (stdin_item && (stdin_item->revents & (ZMQ_POLLIN | ZMQ_POLLERR)))
			if (on_fd_readable(stdin_fd, socket, &stdin_msg, &stdin_msg_valid, msg_type_stdin) == -1)
				goto _out;
		int exited = 0;
		if (socket_item && (socket_item->revents & ZMQ_POLLIN))
			if (on_socket_readable(socket, stdout_fd, stderr_fd, &stdouterr_msg, &stdouterr_msg_pos, &exited, code) == -1)
				goto _out;
		if (exited)
			break;
	}

	rc = 0;

_out:
	if (stdin_msg_valid && zmq_msg_close(&stdin_msg) == -1)
		TRACE_ERRNO("zmq_msg_close() failed");
	if (stdouterr_msg_pos && zmq_msg_close(&stdouterr_msg) == -1)
		TRACE_ERRNO("zmq_msg_close() failed");
	return rc;
}

int main(int argc, char **argv)
{
	int rc = 1;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s ZEROMQ_ENDPOINT\n", argv[0]);
		goto _out;
	}

	void *context = zmq_ctx_new();
	if (context == NULL) {
		TRACE_ERRNO("zmq_ctx_new() failed");
		goto _out;
	}

	void *socket = zmq_socket(context, ZMQ_DEALER);
	if (socket == NULL) {
		TRACE_ERRNO("zmq_socket(%p, ZMQ_DEALER)", context);
		goto _out_free_ctx;
	}

	if (zmq_connect(socket, argv[1]) == -1) {
		TRACE_ERRNO("zmq_connect(%p, %s) failed", socket, argv[1]);
		goto _out_free_socket;
	}

	int stdin_fd = STDIN_FILENO;
	int stdout_fd = STDOUT_FILENO;
	int stderr_fd = STDERR_FILENO;
	int code = 1;
	if (forward(&stdin_fd, &stdout_fd, &stderr_fd, socket, &code) == -1)
		goto _out_free_socket;

	rc = code;

_out_free_socket:
	if (zmq_close(socket) == -1)
		TRACE_ERRNO("zmq_close(%p) failed", socket);

_out_free_ctx:
	if (zmq_ctx_term(context) == -1)
		TRACE_ERRNO("zmq_ctx_term(%p) failed", context);

_out:
	return rc;
}
