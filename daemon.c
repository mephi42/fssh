#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
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

enum msg_type {
	msg_type_stdin = 0,
	msg_type_stdout = 1,
	msg_type_stderr = 2,
	msg_type_exit = 3,
};

static void zmq_free_wrapper(void *data, void *hint)
{
	free(data);
}

static int fd_write(int fd, short *fd_events, zmq_msg_t *msg, size_t *msg_pos)
{
	if (!*msg_pos || (*fd_events & ZMQ_POLLOUT))
		return 0;
	char *msg_data = zmq_msg_data(msg);
	size_t msg_size = zmq_msg_size(msg);
	ssize_t count = write(fd, msg_data + *msg_pos, msg_size - *msg_pos);
	if (count == -1) {
		if (errno == EAGAIN) {
			*fd_events |= ZMQ_POLLOUT;
			return 0;
		}
		TRACE_ERRNO("write(%i, %p, %zu) failed", fd, msg_data + *msg_pos, msg_size - *msg_pos);
		return -1;
	}
	*msg_pos += count;
	if (*msg_pos == msg_size) {
		if (zmq_msg_close(msg) == -1)
			TRACE_ERRNO("zmq_msg_close() failed");
		*msg_pos = 0;
	} else {
		*fd_events |= ZMQ_POLLOUT;
	}
	return 0;
}

static int socket_write(void *socket, short *socket_events, zmq_msg_t *msg, int *msg_valid)
{
	if (!*msg_valid || (*socket_events & ZMQ_POLLOUT))
		return 0;
	if (zmq_msg_send(msg, socket, ZMQ_DONTWAIT) == -1) {
		if (errno == EAGAIN) {
			*socket_events |= ZMQ_POLLOUT;
			return 0;
		}
		TRACE_ERRNO("zmq_msg_write() failed");
		return -1;
	}
	*msg_valid = 0;
	return 0;
}

static int on_fd_readable(int fd, short *fd_events, void *socket, short *socket_events, zmq_msg_t *msg, int *msg_valid, char msg_type)
{
	if (*msg_valid || (*fd_events & ZMQ_POLLIN))
		return 0;
	while (1) {
		const size_t bufsize = 4096;
		char *buf = malloc(bufsize);
		if (buf == NULL) {
			TRACE("malloc(%zu) failed", bufsize);
			return -1;
		}
		buf[0] = msg_type;
		ssize_t count = read(fd, buf + 1, bufsize - 1);
		if (count == -1) {
			if (errno == EAGAIN) {
				free(buf);
				*fd_events |= ZMQ_POLLIN;
				return 0;
			}
			TRACE_ERRNO("read(%i, %p, %zu) failed", fd, buf + 1, bufsize - 1);
			free(buf);
			return -1;
		}
		if (zmq_msg_init_data(msg, buf, count + 1, zmq_free_wrapper, NULL) == -1) {
			TRACE_ERRNO("zmq_msg_init_data() failed");
			free(buf);
			return -1;
		}
		*msg_valid = 1;
		if (socket_write(socket, socket_events, msg, msg_valid) == -1)
			return -1;
		if (count != bufsize - 1) {
			*fd_events |= ZMQ_POLLIN;
			return 0;
		}
	}
}

int on_socket_readable(void *socket, short *socket_events, int stdin_fd, short *stdin_events, zmq_msg_t *stdin_msg, size_t *stdin_msg_pos)
{
	while (1) {
		if (*stdin_msg_pos || (*socket_events & ZMQ_POLLIN))
			return 0;
		if (zmq_msg_init(stdin_msg) == -1) {
			TRACE("zmq_msg_init() failed");
			return -1;
		}
		if (zmq_msg_recv(stdin_msg, socket, ZMQ_DONTWAIT) == -1) {
			if (errno == EAGAIN) {
				*socket_events |= ZMQ_POLLIN;
				return 0;
			}
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
			if (fd_write(stdin_fd, stdin_events,
			             stdin_msg, stdin_msg_pos) == -1)
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

	enum poll_index {
		poll_index_stdin,
		poll_index_stdout,
		poll_index_stderr,
		poll_index_socket,
		poll_index_count,
	};

	zmq_pollitem_t items[poll_index_count];
	memset(&items, 0, sizeof(items));
	items[poll_index_stdin].fd = stdin_pipe[1];
	items[poll_index_stdin].events = 0;
	items[poll_index_stdout].fd = stdout_pipe[0];
	items[poll_index_stdout].events = ZMQ_POLLIN;
	items[poll_index_stderr].fd = stderr_pipe[0];
	items[poll_index_stderr].events = ZMQ_POLLIN;
	items[poll_index_socket].socket = socket;
	items[poll_index_socket].events = ZMQ_POLLIN;

	while (1) {
		if (items[poll_index_stdin].events == 0 &&
		    items[poll_index_stdout].events == 0 &&
		    items[poll_index_stderr].events == 0 &&
		    items[poll_index_socket].events == 0)
			break;
		if (zmq_poll(items, poll_index_count, -1) == -1) {
			TRACE_ERRNO("zmq_poll() failed");
			goto _out;
		}
		items[poll_index_stdin].events = 0;
		items[poll_index_stdout].events = 0;
		items[poll_index_stderr].events = 0;
		items[poll_index_socket].events = 0;

		if ((items[poll_index_stdin].revents & ZMQ_POLLOUT) &&
		    fd_write(items[poll_index_stdin].fd, &items[poll_index_stdin].events,
		             &stdin_msg, &stdin_msg_pos) == -1)
			goto _out;
		if ((items[poll_index_socket].revents & ZMQ_POLLOUT) &&
		    (socket_write(socket, &items[poll_index_socket].events,
		                  &stdout_msg, &stdout_msg_valid) == -1 ||
		     socket_write(socket, &items[poll_index_socket].events,
		                  &stderr_msg, &stderr_msg_valid) == -1))
			goto _out;

		if ((items[poll_index_stdout].revents & ZMQ_POLLIN) &&
		    on_fd_readable(items[poll_index_stdout].fd, &items[poll_index_stdout].events, 
		                   socket, &items[poll_index_socket].events,
		                   &stdout_msg, &stdout_msg_valid, msg_type_stdout) == -1)
			goto _out;
		if ((items[poll_index_stderr].revents & ZMQ_POLLIN) &&
		    on_fd_readable(items[poll_index_stderr].fd, &items[poll_index_stderr].events,
		                   socket, &items[poll_index_socket].events,
		                   &stderr_msg, &stderr_msg_valid, msg_type_stderr) == -1)
			goto _out;
		if ((items[poll_index_socket].revents & ZMQ_POLLIN) &&
		    on_socket_readable(socket, &items[poll_index_socket].events,
		                       items[poll_index_stdin].fd, &items[poll_index_stdin].events,
		                       &stdin_msg, &stdin_msg_pos) == -1)
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
		if (socket_write_exit(socket, status) == -1)
			rc = -1;
	}

_out_free_stderr:
	if (close(stderr_pipe[0]) == -1)
		TRACE_ERRNO("close(%i) failed", stderr_pipe[0]);
	if (stderr_pipe[1] != -1 && close(stderr_pipe[1]) == -1)
		TRACE_ERRNO("close(%i) failed", stderr_pipe[1]);

_out_free_stdout:
	if (close(stdout_pipe[0]) == -1)
		TRACE_ERRNO("close(%i) failed", stdout_pipe[0]);
	if (stdout_pipe[1] != -1 && close(stdout_pipe[1]) == -1)
		TRACE_ERRNO("close(%i) failed", stdout_pipe[1]);

_out_free_stdin:
	if (stdin_pipe[0] != -1 && close(stdin_pipe[0]) == -1)
		TRACE_ERRNO("close(%i) failed", stdin_pipe[0]);
	if (close(stdin_pipe[1]) == -1)
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
