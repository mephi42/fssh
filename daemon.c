#define _GNU_SOURCE

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "message.h"
#include "trace.h"
#include <unistd.h>
#include <zmq.h>

__attribute__((noreturn)) static void execute(char **argv, int stdin_pipe[2], int stdout_pipe[2], int stderr_pipe[2])
{
	if (dup2(stdin_pipe[0], STDIN_FILENO) == -1) {
		TRACE_ERRNO("dup2(%i, %i) failed", stdin_pipe[0], STDIN_FILENO);
		goto _fail;
	}
	if (close(stdin_pipe[0]) == -1)
		TRACE_ERRNO("close(%i) failed", stdin_pipe[0]);
	if (close(stdin_pipe[1]) == -1)
		TRACE_ERRNO("close(%i) failed", stdin_pipe[1]);

	if (dup2(stdout_pipe[1], STDOUT_FILENO) == -1) {
		TRACE_ERRNO("dup2(%i, %i) failed", stdout_pipe[1], STDOUT_FILENO);
		goto _fail;
	}
	if (close(stdout_pipe[0]) == -1)
		TRACE_ERRNO("close(%i) failed", stdout_pipe[0]);
	if (close(stdout_pipe[1]) == -1)
		TRACE_ERRNO("close(%i) failed", stdout_pipe[1]);

	if (dup2(stderr_pipe[1], STDERR_FILENO) == -1) {
		TRACE_ERRNO("dup2(%i, %i) failed", stderr_pipe[1], STDERR_FILENO);
		goto _fail;
	}
	if (close(stderr_pipe[0]) == -1)
		TRACE_ERRNO("close(%i) failed", stderr_pipe[0]);
	if (close(stderr_pipe[1]) == -1)
		TRACE_ERRNO("close(%i) failed", stderr_pipe[1]);

	if (execvp(argv[0], argv) == -1) {
		TRACE_ERRNO("execvp(%s) failed", argv[0]);
		goto _fail;
	}

_fail:
	_exit(1);
}

static void zmq_free_wrapper(void *data, void *hint)
{
	free(data);
}

static int fd_write(int *fd, zmq_msg_t *msg, size_t *msg_pos)
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

static int socket_write(void *socket, zmq_msg_t *msg, int *msg_valid)
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

static int on_fd_readable(int *fd, void *socket, zmq_msg_t *msg, int *msg_valid, char msg_type)
{
	if (*msg_valid)
		return 0;
	while (1) {
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
		if (count == 0) {
			if (close(*fd))
				TRACE_ERRNO("close(%i) failed", *fd);
			*fd = -1;
			return 0;
		}
	}
}

int on_socket_readable(void *socket, int *stdin_fd, zmq_msg_t *stdin_msg, size_t *stdin_msg_pos)
{
	while (1) {
		if (*stdin_msg_pos)
			return 0;
		if (zmq_msg_init(stdin_msg) == -1) {
			TRACE("zmq_msg_init() failed");
			return -1;
		}
		if (zmq_msg_recv(stdin_msg, socket, ZMQ_DONTWAIT) == -1) {
			if (errno == EAGAIN)
				return 0;
			TRACE_ERRNO("zmq_msg_recv() failed");
			return -1;
		}
		if (zmq_msg_size(stdin_msg) == 0) {
			TRACE("empty message received");
			return -1;
		}
		char *msg_data = zmq_msg_data(stdin_msg);
		if (msg_data[0] == msg_type_stdin) {
			*stdin_msg_pos = 1;
			if (fd_write(stdin_fd, stdin_msg, stdin_msg_pos) == -1)
				return -1;
		} else {
			TRACE("message with unexpected type received");
			return -1;
		}	
	}
}

static int forward(pid_t pid, int stdin_pipe[2], int stdout_pipe[2], int stderr_pipe[2], void *socket)
{
	int rc = -1;

	if (close(stdin_pipe[0]) == -1)
		TRACE_ERRNO("close(%i) failed", stdin_pipe[0]);
	stdin_pipe[0] = -1;

	if (close(stdout_pipe[1]) == -1)
		TRACE_ERRNO("close(%i) failed", stdout_pipe[1]);
	stdout_pipe[1] = -1;

	if (close(stderr_pipe[1]) == -1)
		TRACE_ERRNO("close(%i) failed", stderr_pipe[1]);
	stderr_pipe[1] = -1;

	zmq_msg_t stdin_msg;
	size_t stdin_msg_pos = 0;
	zmq_msg_t stdout_msg;
	int stdout_msg_valid = 0;
	zmq_msg_t stderr_msg;
	int stderr_msg_valid = 0;

	while (1) {
		zmq_pollitem_t items[4];
		zmq_pollitem_t *item = items;

		zmq_pollitem_t *stdin_item = NULL;
		if (stdin_pipe[1] != -1 && stdin_msg_pos) {
			stdin_item = item++;
			stdin_item->socket = NULL;
			stdin_item->fd = stdin_pipe[1];
			stdin_item->events = ZMQ_POLLOUT | ZMQ_POLLERR;
		}

		zmq_pollitem_t *stdout_item = NULL;
		if (stdout_pipe[0] != -1 && !stdout_msg_valid) {
			stdout_item = item++;
			stdout_item->socket = NULL;
			stdout_item->fd = stdout_pipe[0];
			stdout_item->events = ZMQ_POLLIN | ZMQ_POLLERR;
		}

		zmq_pollitem_t *stderr_item = NULL;
		if (stderr_pipe[0] != -1 && !stderr_msg_valid) {
			stderr_item = item++;
			stderr_item->socket = NULL;
			stderr_item->fd = stderr_pipe[0];
			stderr_item->events = ZMQ_POLLIN | ZMQ_POLLERR;
		}

		zmq_pollitem_t *socket_item = NULL;
		short socket_events = ((stdout_msg_valid || stderr_msg_valid) ? ZMQ_POLLOUT : 0) |
		                      ((stdin_pipe[1] == -1 || stdin_msg_pos) ? 0 : ZMQ_POLLIN);
		if (socket_events) {
			socket_item = item++;
			socket_item->socket = socket;
			socket_item->fd = -1;
			socket_item->events = socket_events;
		}

		if (item == items)
			break;

		while (1) {
			if (zmq_poll(items, item - items, -1) == -1) {
				if (errno == EINTR)
					continue;
				TRACE_ERRNO("zmq_poll() failed");
				goto _out;
			}
			break;
		}

		if (stdin_item && (stdin_item->revents & (ZMQ_POLLOUT | ZMQ_POLLERR)))
			if (fd_write(&stdin_pipe[1], &stdin_msg, &stdin_msg_pos) == -1)
				goto _out;
		if (socket_item && (socket_item->revents & ZMQ_POLLOUT)) {
			if (socket_write(socket, &stdout_msg, &stdout_msg_valid) == -1)
				goto _out;
			if (socket_write(socket, &stderr_msg, &stderr_msg_valid) == -1)
				goto _out;
		}
		if (stdout_item && (stdout_item->revents & (ZMQ_POLLIN | ZMQ_POLLERR)))
			if (on_fd_readable(&stdout_pipe[0], socket, &stdout_msg, &stdout_msg_valid, msg_type_stdout) == -1)
				goto _out;
		if (stderr_item && (stderr_item->revents & (ZMQ_POLLIN | ZMQ_POLLERR)))
			if (on_fd_readable(&stderr_pipe[0], socket, &stderr_msg, &stderr_msg_valid, msg_type_stderr) == -1)
				goto _out;
		if (socket_item && (socket_item->revents & ZMQ_POLLIN))
			if (on_socket_readable(socket, &stdin_pipe[1], &stdin_msg, &stdin_msg_pos) == -1)
				goto _out;
	}

	rc = 0;

_out:
	if (stdin_msg_pos && zmq_msg_close(&stdin_msg))
		TRACE_ERRNO("zmq_msg_close() failed");
	if (stdout_msg_valid && zmq_msg_close(&stdout_msg))
		TRACE_ERRNO("zmq_msg_close() failed");
	if (stderr_msg_valid && zmq_msg_close(&stderr_msg))
		TRACE_ERRNO("zmq_msg_close() failed");
	return rc;
}

static int socket_write_exit(void *socket, int status)
{
	zmq_msg_t msg;
	if (zmq_msg_init_size(&msg, 5) == -1) {
		TRACE_ERRNO("zmq_msg_init_size() failed");
		return -1;
	}

	char *data = zmq_msg_data(&msg);
	data[0] = msg_type_exit;
	*(int32_t*)&data[1] = (int32_t)status;

	if (zmq_msg_send(&msg, socket, 0) == -1) {
		TRACE_ERRNO("zmq_msg_send() failed");
		if (zmq_msg_close(&msg) == -1)
			TRACE_ERRNO("zmq_msg_close() failed");
		return -1;
	}

	return 0;
}

static int execute_and_forward(char **argv, void *socket)
{
	int rc = -1;

	int stdin_pipe[2];
	if (pipe(stdin_pipe) == -1) {
		TRACE_ERRNO("pipe(stdin_pipe) failed");
		goto _out;
	}

	int stdout_pipe[2];
	if (pipe(stdout_pipe) == -1) {
		TRACE_ERRNO("pipe(stdout_pipe) failed");
		goto _out_free_stdin;
	}

	int stderr_pipe[2];
	if (pipe(stderr_pipe) == -1) {
		TRACE_ERRNO("pipe(stderr_pipe) failed");
		goto _out_free_stdout;
	}

	pid_t pid = fork();
	if (pid == -1) {
		TRACE_ERRNO("fork() failed");
		goto _out_free_stderr;
	}
	if (pid == 0)
		execute(argv, stdin_pipe, stdout_pipe, stderr_pipe);

	if (forward(pid, stdin_pipe, stdout_pipe, stderr_pipe, socket) == -1)
		goto _out_wait;

	rc = 0;

_out_wait:
	if (rc == -1 && kill(pid, SIGKILL) == -1)
		TRACE_ERRNO("kill(%i, SIGKILL) failed", pid);
	int status;
	if (waitpid(pid, &status, 0) == -1) {
		TRACE_ERRNO("waitpid(%i) failed", pid);
	} else if (rc == 0) {
		TRACE("%s (%i) exited with status %i", argv[0], pid, status);
		int code;
		if (WIFEXITED(status))
			code = WEXITSTATUS(status);
		else
			code = 1;
		if (socket_write_exit(socket, code) == -1)
			rc = -1;
	}

_out_free_stderr:
	if (stderr_pipe[0] != -1 && close(stderr_pipe[0]) == -1)
		TRACE_ERRNO("close(%i) failed", stderr_pipe[0]);
	if (stderr_pipe[1] != -1 && close(stderr_pipe[1]) == -1)
		TRACE_ERRNO("close(%i) failed", stderr_pipe[1]);

_out_free_stdout:
	if (stdout_pipe[0] != -1 && close(stdout_pipe[0]) == -1)
		TRACE_ERRNO("close(%i) failed", stdout_pipe[0]);
	if (stdout_pipe[1] != -1 && close(stdout_pipe[1]) == -1)
		TRACE_ERRNO("close(%i) failed", stdout_pipe[1]);

_out_free_stdin:
	if (stdin_pipe[0] != -1 && close(stdin_pipe[0]) == -1)
		TRACE_ERRNO("close(%i) failed", stdin_pipe[0]);
	if (stdin_pipe[1] != -1 && close(stdin_pipe[1]) == -1)
		TRACE_ERRNO("close(%i) failed", stdin_pipe[1]);

_out:
	return rc;
}

int main(int argc, char **argv)
{
	int rc = 1;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s ZEROMQ_ENDPOINT PGM [ARGS]...\n", argv[0]);
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

	if (zmq_bind(socket, argv[1]) == -1) {
		TRACE_ERRNO("zmq_bind(%p, %s) failed", socket, argv[1]);
		goto _out_free_socket;
	}

	if (execute_and_forward(argv + 2, socket) == -1)
		goto _out_free_socket;

	rc = 0;

_out_free_socket:
	if (zmq_close(socket) == -1)
		TRACE_ERRNO("zmq_close(%p) failed", socket);

_out_free_ctx:
	if (zmq_ctx_term(context) == -1)
		TRACE_ERRNO("zmq_ctx_term(%p) failed", context);

_out:
	return rc;
}
