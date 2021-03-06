#define _GNU_SOURCE

#include "anyzmq.h"
#include <arpa/inet.h>
#include "child.h"
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "message.h"
#include "nonblock.h"
#include "reset.h"
#include "trace.h"
#include <unistd.h>

static int on_socket_readable(void *socket, int *stdin_fd, zmq_msg_t *stdin_msg, size_t *stdin_msg_pos, int *exp_seq)
{
	while (1) {
		if (*stdin_msg_pos)
			return 0;
		if (zmq_msg_init(stdin_msg) == -1) {
			TRACE_ERRNO("zmq_msg_init() failed");
			return -1;
		}
		if (zmq_msg_recv(stdin_msg, socket, ZMQ_DONTWAIT) == -1) {
			if (errno == EAGAIN)
				return 0;
			TRACE_ERRNO("zmq_msg_recv() failed");
			return -1;
		}
		size_t msg_size = zmq_msg_size(stdin_msg);
		if (msg_size == 0) {
			TRACE("empty message received");
			return -1;
		}
		int msg_hdr = get_msg_hdr(stdin_msg);
		int msg_type = MSG_HDR_TYPE(msg_hdr);
		int msg_seq = MSG_HDR_SEQ(msg_hdr);
		TRACE("received message, type=%i, seq=%i, size=%zu", msg_type, msg_seq, msg_size);
		if (msg_seq != *exp_seq) {
			TRACE("warning: exp_seq=%i", *exp_seq);
			*exp_seq = msg_seq;
		}
		*exp_seq = ((*exp_seq) + 1) & MSG_HDR_SEQ_MASK;
		if (msg_type == msg_type_stdin) {
			*stdin_msg_pos = 1;
			if (fd_write(stdin_fd, stdin_msg, stdin_msg_pos) == -1)
				return -1;
		} else {
			TRACE("message with unexpected type received");
			return -1;
		}	
	}
}

static int on_sigchld(int *sigchld_fd, pid_t pid, int *stdin_fd)
{
	struct signalfd_siginfo si;
	ssize_t count = read(*sigchld_fd, &si, sizeof(si));
	if (count == -1) {
		if (errno == EAGAIN)
			return 0;
		TRACE_ERRNO("read(%i, %p, %zu) failed", *sigchld_fd, &si, sizeof(si));
		return -1;
	}
	TRACE("signal received: signo=%i, code=%i, pid=%i", si.ssi_signo, si.ssi_code, si.ssi_pid);
	if (si.ssi_signo != SIGCHLD || si.ssi_code != CLD_EXITED || (pid_t)si.ssi_pid != pid)
		return 0;
	if (reset_fd(sigchld_fd) == -1)
		return -1;
	if (reset_fd(stdin_fd) == -1)
		return -1;
	return 0;
}

static int forward(pid_t pid, int *sigchld_fd, int stdin_pipe[2], int stdout_pipe[2], int stderr_pipe[2], void *socket)
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

	int msg_seq = 0;
	int exp_seq = 0;
	zmq_msg_t stdin_msg;
	size_t stdin_msg_pos = 0;
	zmq_msg_t stdout_msg;
	int stdout_msg_valid = 0;
	zmq_msg_t stderr_msg;
	int stderr_msg_valid = 0;

	if (make_nonblocking(stdin_pipe[1]) == -1)
		goto _out;
	if (make_nonblocking(stdout_pipe[0]) == -1)
		goto _out;
	if (make_nonblocking(stderr_pipe[0]) == -1)
		goto _out;
	TRACE("made nonblocking: %i, %i, %i", stdin_pipe[1], stdout_pipe[0], stderr_pipe[0]);

	while (1) {
		zmq_pollitem_t items[5];
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

		zmq_pollitem_t *sigchld_item = NULL;
		if (*sigchld_fd != -1) {
			sigchld_item = item++;
			sigchld_item->socket = NULL;
			sigchld_item->fd = *sigchld_fd;
			sigchld_item->events = ZMQ_POLLIN | ZMQ_POLLERR;
		}

		if (item == items) {
			TRACE("nothing to poll, exiting");
			break;
		}

		TRACE("polling:%s%s%s%s%s", stdin_item ? " stdin" : "",
		                            stdout_item ? " stdout" : "",
		                            stderr_item ? " stderr" : "",
		                            socket_item ? " socket" : "",
		                            sigchld_item ? " sigchld" : "");

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
			if (on_fd_readable(&stdout_pipe[0], socket, &stdout_msg, &stdout_msg_valid, msg_type_stdout, &msg_seq) == -1)
				goto _out;
		if (stderr_item && (stderr_item->revents & (ZMQ_POLLIN | ZMQ_POLLERR)))
			if (on_fd_readable(&stderr_pipe[0], socket, &stderr_msg, &stderr_msg_valid, msg_type_stderr, &msg_seq) == -1)
				goto _out;
		if (socket_item && (socket_item->revents & ZMQ_POLLIN))
			if (on_socket_readable(socket, &stdin_pipe[1], &stdin_msg, &stdin_msg_pos, &exp_seq) == -1)
				goto _out;
		if (sigchld_item && (sigchld_item->revents & (ZMQ_POLLIN | ZMQ_POLLERR)))
			if (on_sigchld(sigchld_fd, pid, &stdin_pipe[1]) == -1)
				goto _out;
	}

	rc = 0;

_out:
	if (stdin_msg_pos && zmq_msg_close(&stdin_msg) == -1)
		TRACE_ERRNO("zmq_msg_close() failed");
	if (stdout_msg_valid && zmq_msg_close(&stdout_msg) == -1)
		TRACE_ERRNO("zmq_msg_close() failed");
	if (stderr_msg_valid && zmq_msg_close(&stderr_msg) == -1)
		TRACE_ERRNO("zmq_msg_close() failed");
	return rc;
}

static int socket_write_exit(void *socket, int code)
{
	zmq_msg_t msg;
	if (zmq_msg_init_size(&msg, 5) == -1) {
		TRACE_ERRNO("zmq_msg_init_size() failed");
		return -1;
	}

	char *data = zmq_msg_data(&msg);
	data[0] = MSG_HDR(msg_type_exit, 0);
	*(uint32_t*)&data[1] = htonl((uint32_t)code);

	if (zmq_msg_send(&msg, socket, 0) == -1) {
		TRACE_ERRNO("zmq_msg_send() failed");
		if (zmq_msg_close(&msg) == -1)
			TRACE_ERRNO("zmq_msg_close() failed");
		return -1;
	}
	TRACE("sent exit message, code=%i", code);

	return 0;
}

static int execute_and_forward(char **argv, void *socket)
{
	int rc = -1;

	struct child child;
	if (child_init(&child, argv) == -1) {
		TRACE("child_init() failed");
		goto _out;
	}

	if (forward(child.pid, &child.sigchld_fd, child.pipes.stdin_pipe, child.pipes.stdout_pipe, child.pipes.stderr_pipe, socket) == -1)
		goto _out_wait;

	rc = 0;

_out_wait:
	if (rc == -1 && kill(child.pid, SIGKILL) == -1)
		TRACE_ERRNO("kill(%i, SIGKILL) failed", child.pid);
	int status;
	if (waitpid(child.pid, &status, 0) == -1) {
		TRACE_ERRNO("waitpid(%i) failed", child.pid);
	} else if (rc == 0) {
		TRACE("%s (%i) exited with status %i", argv[0], child.pid, status);
		int code;
		if (WIFEXITED(status))
			code = WEXITSTATUS(status);
		else
			code = 1;
		if (socket_write_exit(socket, code) == -1)
			rc = -1;
	}

	if (child_reset(&child) == -1)
		TRACE("child_reset() failed");

_out:
	return rc;
}

static int lock_ipc_endpoint(char *ipc)
{
	size_t ipc_len = strlen(ipc);
	static const char suffix[] = ".lock";
	char lock[ipc_len + sizeof(suffix)];
	snprintf(lock, sizeof(lock), "%s%s", ipc, suffix);

	int fd = open(lock, O_WRONLY | O_CLOEXEC | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		TRACE_ERRNO("open(%s) failed", lock);
		goto _out;
	}

	if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
		TRACE_ERRNO("flock() failed");
		if (close(fd) == -1)
			TRACE_ERRNO("close(%i) failed", fd);
		fd = -1;
		goto _out;
	}

_out:
	return fd;
}

static int lock_endpoint(char *endpoint)
{
	if (endpoint[0] == 'i' &&
	    endpoint[1] == 'p' &&
	    endpoint[2] == 'c' &&
	    endpoint[3] == ':' &&
	    endpoint[4] == '/')
		return lock_ipc_endpoint(endpoint + 5);
	return 0;
}

int main(int argc, char **argv)
{
	for (int i = 0; i < argc; ++i)
	{
		TRACE("argv[%i] = %s", i, argv[i]);
	}

	int rc = 1;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s ZEROMQ_ENDPOINT PGM [ARGS]...\n", argv[0]);
		goto _out;
	}

	if (lock_endpoint(argv[1]) == -1)
		goto _out;

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
