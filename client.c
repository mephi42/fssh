#include "message.h"
#include <stdio.h>
#include <stdint.h>
#include "trace.h"
#include <unistd.h>
#include <zmq.h>

static int writeall(int fd, const void *buf, size_t count)
{
	while (count) {
		size_t written = write(fd, buf, count);
		if (written == -1)
			return -1;
		buf += written;
		count -= written;
	}
	return 0;
}

static int forward(void *socket, int *status)
{
	int rc = -1;

	zmq_msg_t msg;
	if (zmq_msg_init(&msg) == -1) {
		TRACE_ERRNO("zmq_msg_init() failed");
		goto _out;
	}

	while (1) {
		if (zmq_msg_recv(&msg, socket, 0) == -1) {
			TRACE_ERRNO("zmq_msg_recv() failed");
			goto _out_free_msg;
		}

		size_t msg_size = zmq_msg_size(&msg);
		if (msg_size == 0) {
			TRACE("empty message received");
			goto _out_free_msg;
		}

		char *msg_data = zmq_msg_data(&msg);
		if (msg_data[0] == msg_type_stdout) {
			if (writeall(STDOUT_FILENO, msg_data + 1, msg_size - 1) == -1)
				goto _out_free_msg;
		} else if(msg_data[0] == msg_type_stderr) {
			if (writeall(STDERR_FILENO, msg_data + 1, msg_size - 1) == -1)
				goto _out_free_msg;
		} else if(msg_data[0] == msg_type_exit) {
			*status = (int)(*(uint32_t*)&msg_data[1]);
			break;
		} else {
			TRACE("message with unexpected type received");
			goto _out_free_msg;
		}
	}

	rc = 0;

_out_free_msg:
	if (zmq_msg_close(&msg) == -1)
		TRACE_ERRNO("zmq_msg_close() failed");

_out:
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

	int status = 1;
	if (forward(socket, &status) == -1)
		goto _out_free_socket;

	rc = status;

_out_free_socket:
	if (zmq_close(socket) == -1)
		TRACE_ERRNO("zmq_close(%p) failed", socket);

_out_free_ctx:
	if (zmq_ctx_term(context) == -1)
		TRACE_ERRNO("zmq_ctx_term(%p) failed", context);

_out:
	return rc;
}
