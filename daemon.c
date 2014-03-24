#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <event2/event.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "nonblock.h"
#include "ringbuf.h"
#include "sigutils.h"
#include "trace.h"
#include "un.h"

#define READ_END 0
#define WRITE_END 1

struct pipes {
	int stdin[2];
	int stdout[2];
	int stderr[2];
};

int pipes_init(struct pipes *pipes)
{
	if (pipe(pipes->stdin) == -1) {
		TRACE_ERRNO("pipe() failed");
		goto _fail_stdin;
	}
	if (pipe(pipes->stdout) == -1) {
		TRACE_ERRNO("pipe() failed");
		goto _fail_stdout;
	}
	if (pipe(pipes->stderr) == -1) {
		TRACE_ERRNO("pipe() failed");
		goto _fail_stderr;
	}
	return 0;

_fail_stderr:
	if (close(pipes->stdout[READ_END]) == -1)
		TRACE_ERRNO("close(%d) failed", pipes->stdout[READ_END]);
	if (close(pipes->stdout[WRITE_END]) == -1)
		TRACE_ERRNO("close(%d) failed", pipes->stdout[WRITE_END]);
_fail_stdout:
	if (close(pipes->stdin[READ_END]) == -1)
		TRACE_ERRNO("close(%d) failed", pipes->stdin[READ_END]);
	if (close(pipes->stdin[WRITE_END]) == -1)
		TRACE_ERRNO("close(%d) failed", pipes->stdin[WRITE_END]);
_fail_stdin:
	return -1;
}

int pipes_reset(struct pipes *pipes)
{
	int rc = 0;
	if (pipes->stdin[READ_END] != -1 && close(pipes->stdin[READ_END]) == -1) {
		TRACE_ERRNO("close(%d) failed", pipes->stdin[READ_END]);
		rc = -1;
	}
	if (pipes->stdin[WRITE_END] != -1 && close(pipes->stdin[WRITE_END]) == -1) {
		TRACE_ERRNO("close(%d) failed", pipes->stdin[WRITE_END]);
		rc = -1;
	}
	if (pipes->stdout[READ_END] != -1 && close(pipes->stdout[READ_END]) == -1) {
		TRACE_ERRNO("close(%d) failed", pipes->stdin[WRITE_END]);
		rc = -1;
	}
	if (pipes->stdout[WRITE_END] != -1 && close(pipes->stdout[WRITE_END]) == -1) {
		TRACE_ERRNO("close(%d) failed", pipes->stdout[WRITE_END]);
		rc = -1;
	}
	if (pipes->stderr[READ_END] != -1 && close(pipes->stderr[READ_END]) == -1) {
		TRACE_ERRNO("close(%d) failed", pipes->stderr[READ_END]);
		rc = -1;
	}
	if (pipes->stderr[WRITE_END] != -1 && close(pipes->stderr[WRITE_END]) == -1) {
		TRACE_ERRNO("close(%d) failed", pipes->stderr[WRITE_END]);
		rc = -1;
	}
	return rc;
}

int handle_pipes_in_child(struct pipes *pipes)
{
	int rc = -1;
	if (dup2(pipes->stdin[READ_END], STDIN_FILENO) == -1) {
		TRACE_ERRNO("dup2(%d, 0) failed", pipes->stdin[READ_END]);
		goto _out;
	}
	if (dup2(pipes->stdout[WRITE_END], STDOUT_FILENO) == -1) {
		TRACE_ERRNO("dup2(%d, 1) failed", pipes->stdout[WRITE_END]);
		goto _out;
	}
	if (dup2(pipes->stderr[WRITE_END], STDERR_FILENO) == -1) {
		TRACE_ERRNO("dup2(%d, 2) failed", pipes->stderr[WRITE_END]);
		goto _out;
	}
	if (pipes_reset(pipes) == -1) {
		TRACE("pipes_reset() failed");
		goto _out;
	}
	rc = 0;
_out:
	return rc;
}

int handle_pipes_in_parent(struct pipes *pipes)
{
	int rc = -1;
	if (close(pipes->stdin[READ_END]) == -1) {
		TRACE_ERRNO("close(%d) failed", pipes->stdin[READ_END]);
		goto _out;
	}
	pipes->stdin[READ_END] = -1;
	if (close(pipes->stdout[WRITE_END]) == -1) {
		TRACE_ERRNO("close(%d) failed", pipes->stdout[WRITE_END]);
		goto _out;
	}
	pipes->stdout[WRITE_END] = -1;
	if (close(pipes->stderr[WRITE_END]) == -1) {
		TRACE_ERRNO("close(%d) failed", pipes->stderr[WRITE_END]);
		goto _out;
	}
	pipes->stderr[WRITE_END] = -1;
	if (make_nonblocking(pipes->stdin[WRITE_END]) == -1) {
		TRACE("make_nonblocking(%d) failed", pipes->stdin[WRITE_END]);
		goto _out;
	}
	if (make_nonblocking(pipes->stdout[READ_END]) == -1) {
		TRACE("make_nonblocking(%d) failed", pipes->stdout[READ_END]);
		goto _out;
	}
	if (make_nonblocking(pipes->stderr[READ_END]) == -1) {
		TRACE("make_nonblocking(%d) failed", pipes->stderr[READ_END]);
		goto _out;
	}
	rc = 0;
_out:
	return rc;
}

struct fwd {
	int socket_fd;
	int stdin_fd;
	int stdout_fd;
	int stderr_fd;
	int socket_eof;
	int stdout_eof;
	int stderr_eof;
	struct ringbuf to_socket;
	struct ringbuf from_socket;
	struct event_base *base;
	struct event *stdin;
	struct event *stdout;
	struct event *stderr;
	struct event *socket_read;
	struct event *socket_write;
	struct event *sigchld;
	int exited;
	int status;
};

void fwd_break(struct event_base *base)
{
	if (event_base_loopbreak(base) == -1)
	        TRACE("event_base_loopbreak(%p) failed", base);
}

struct message {
	uint8_t type;
	uint8_t stream_id;
	uint16_t length;
	char data[];
} __attribute__((packed));

#define MESSAGE_DATA 0
#define MESSAGE_STATUS 1
#define MESSAGE_ACK 2
#define MESSAGE_STDIN 0
#define MESSAGE_STDOUT 1
#define MESSAGE_STDERR 2
#define THRESHOLD 80

int fwd_read(struct fwd *fwd, int fd, int *eof, int stream_id)
{
	size_t max = ringbuf_max_write(&fwd->to_socket);
	if (max < sizeof(struct message) + THRESHOLD)
		return 0;
	struct message *msg = (struct message *)fwd->to_socket.write;
	ssize_t count = read(fd, msg->data, max - sizeof(struct message));
	if (count == -1) {
		if (errno == EAGAIN)
			return 0;
		TRACE_ERRNO("read(%d, %p, %d) failed", fd, &msg->data, max - sizeof(struct message));
		return -1;
	}
	if (count == 0) {
		*eof = 1;
		return 0;
	}
	msg->type = MESSAGE_DATA;
	msg->stream_id = stream_id;
	msg->length = htons(sizeof(struct message) + count);
	ringbuf_write(&fwd->to_socket, sizeof(struct message) + count);
	return 0;
}

int fwd_write_socket(struct fwd *fwd)
{
	size_t max = ringbuf_max_read(&fwd->to_socket);
	if (max == 0)
		return 0;
	ssize_t count = write(fwd->socket_fd, fwd->to_socket.read, max);
	if (count == -1) {
		if (errno == EAGAIN)
			return 0;
		TRACE_ERRNO("write(%d) failed", fwd->socket_fd);
		return -1;
	}
	ringbuf_read(&fwd->to_socket, count);
	return 0;
}

int fwd_read_more(struct fwd *fwd, struct event *event, int eof)
{
	if (eof || ringbuf_max_write(&fwd->to_socket) < sizeof(struct message) + THRESHOLD)
	        return 0;
	if (event_add(event, NULL) == -1) {
	        TRACE("event_add(%p) failed", event);
	        return -1;
	}
	return 0;
}

int fwd_write_socket_more(struct fwd *fwd)
{
	if (ringbuf_max_read(&fwd->to_socket) == 0)
	        return 0;
	if (event_add(fwd->socket_write, NULL) == -1) {
	        TRACE("event_add(%p) failed", fwd->socket_write);
	        return -1;
	}
	return 0;
}

void on_outstream(struct fwd *fwd, int fd, int *eof, int stream_id, struct event *event)
{
	if (fwd_read(fwd, fd, eof, stream_id) == -1) {
		TRACE("fwd_read_stdout(%p) failed", fwd);
		goto _fail;
	}
	if (fwd_write_socket(fwd) == -1) {
		TRACE("fwd_write_socket(%p) failed", fwd);
		goto _fail;
	}
	if (fwd_read_more(fwd, event, *eof) == -1) {
		TRACE("fwd_read_stdout_more(%p) failed", fwd);
		goto _fail;
	}
	if (fwd_write_socket_more(fwd) == -1) {
		TRACE("fwd_write_socket_more(%p) failed", fwd);
		goto _fail;
	}
	return;

_fail:
	fwd_break(event_get_base(event));
}

void on_stdin(int fd, short events, void *arg)
{
}

void on_stdout(int fd, short events, void *arg)
{
	struct fwd *fwd = arg;
	on_outstream(fwd, fwd->stdout_fd, &fwd->stdout_eof, MESSAGE_STDOUT, fwd->stdout);
}

void on_stderr(int fd, short events, void *arg)
{
	struct fwd *fwd = arg;
	on_outstream(fwd, fwd->stderr_fd, &fwd->stderr_eof, MESSAGE_STDERR, fwd->stderr);
}

int fwd_read_socket(struct fwd *fwd)
{
	size_t max = ringbuf_max_write(&fwd->from_socket);
	if (max == 0)
		return 0;
	ssize_t count = read(fwd->socket_fd, fwd->from_socket.write, max);
	if (count == -1) {
		if (errno == EAGAIN)
			return 0;
		TRACE_ERRNO("read(%d, %p, %d) failed", fwd->socket_fd, &fwd->from_socket.write, max);
		return -1;
	}
	if (count == 0) {
		fwd->socket_eof = 1;
		return 0;
	}
	ringbuf_write(&fwd->from_socket, count);
	return 0;
}

int fwd_handle_socket_buffer(struct fwd *fwd)
{
	while (1) {
		size_t max = ringbuf_max_read(&fwd->from_socket);
		if (max < sizeof(struct message))
			return 0;
		struct message *msg = fwd->from_socket.read;
		size_t len = ntohs(msg->length);
		if (max < len)
			return 0;
		switch(msg->type) {
		case MESSAGE_DATA:
			if (msg->stream_id != MESSAGE_STDIN) {
				TRACE("Unexpected stream %d", msg->stream_id);
				return -1;
			}
			ssize_t count = write(fwd->stdin_fd, msg->data, len - sizeof(struct message));
			if (count == -1) {
				TRACE_ERRNO("write(%d, %p, %d) failed", fwd->stdin_fd, &msg->data, len - sizeof(struct message));
				return -1;
			}
			if (count != len - sizeof(struct message)) {
				TRACE("TODO: implement incomplete stdin writes");
				return -1;
			}
		default:
			TRACE("Unexpected message type %d", msg->type);
			return -1;
		}
		ringbuf_read(&fwd->from_socket, len);
	}
}

int fwd_read_socket_more(struct fwd *fwd)
{
	if (fwd->socket_eof || ringbuf_max_read(&fwd->from_socket) == 0)
		return 0;
	if (event_add(fwd->socket_read, NULL) == -1) {
		TRACE("event_add(%p) failed", fwd->socket_read);
		return -1;
	}
	return 0;
}

void on_socket_read(int fd, short events, void *arg)
{
	struct fwd *fwd = arg;
	if (fwd_read_socket(fwd) == -1) {
		TRACE("fwd_read_socket() failed");
		goto _fail;
	}
	if (fwd_handle_socket_buffer(fwd) == -1) {
		TRACE("fwd_handle_socket_buffer() failed");
		goto _fail;
	}
	if (fwd_read_socket_more(fwd) == -1) {
		TRACE("fwd_read_socket_more() failed");
		goto _fail;
	}
	return;

_fail:
	fwd_break(fwd->base);
}

void on_socket_write(int fd, short events, void *arg)
{
}

void on_sigchld(int fd, short events, void *arg)
{
	struct fwd *fwd = arg;
	if (wait(&fwd->status) == -1) {
		TRACE_ERRNO("wait() failed");
		goto _fail;
	}
	fwd->exited = 1;
	TRACE("TODO: add exit code message");
	return;

_fail:
	fwd_break(fwd->base);
}

int fwd_init(struct fwd *fwd, int socket_fd, int stdin_fd, int stdout_fd, int stderr_fd)
{
	fwd->socket_fd = socket_fd;
	fwd->stdin_fd = stdin_fd;
	fwd->stdout_fd = stdout_fd;
	fwd->stderr_fd = stderr_fd;
	fwd->socket_eof = 0;
	fwd->stdout_eof = 0;
	fwd->stderr_eof = 0;
	fwd->exited = 0;
	fwd->status = 0;

	if (ringbuf_init(&fwd->to_socket, 4096) == -1) {
		TRACE("ringbuf_init() failed");
		goto _fail_to_socket;
	}

	if (ringbuf_init(&fwd->from_socket, 4096) == -1) {
		TRACE("ringbuf_init() failed");
		goto _fail_from_socket;
	}

	fwd->base = event_base_new();
	if (fwd->base == NULL) {
		TRACE("event_base_new() failed");
		goto _fail_base;
	}

	fwd->stdin = event_new(fwd->base, stdin_fd, EV_WRITE, &on_stdin, fwd);
	if (fwd->stdin == NULL) {
		TRACE("event_new() failed");
		goto _fail_stdin;
	}

	fwd->stdout = event_new(fwd->base, stdout_fd, EV_READ, &on_stdout, fwd);
	if (fwd->stdout == NULL) {
		TRACE("event_new() failed");
		goto _fail_stdout;
	}

	fwd->stderr = event_new(fwd->base, stderr_fd, EV_READ, &on_stderr, fwd);
	if (fwd->stderr == NULL) {
		TRACE("event_new() failed");
		goto _fail_stderr;
	}

	fwd->socket_read = event_new(fwd->base, socket_fd, EV_READ, &on_socket_read, fwd);
	if (fwd->socket_read == NULL) {
		TRACE("event_new() failed");
		goto _fail_socket_read;
	}

	fwd->socket_write = event_new(fwd->base, socket_fd, EV_WRITE, &on_socket_write, fwd);
	if (fwd->socket_write == NULL) {
		TRACE("event_new() failed");
		goto _fail_socket_write;
	}

	fwd->sigchld = event_new(fwd->base, SIGCHLD, EV_SIGNAL, &on_sigchld, fwd);
	if (fwd->sigchld == NULL) {
		TRACE("event_new() failed");
		goto _fail_sigchld;
	}

	return 0;

_fail_sigchld:
	event_free(fwd->socket_write);
_fail_socket_write:
	event_free(fwd->socket_read);
_fail_socket_read:
	event_free(fwd->stderr);
_fail_stderr:
	event_free(fwd->stdout);
_fail_stdout:
	event_free(fwd->stdin);
_fail_stdin:
	event_base_free(fwd->base);
_fail_base:
	if (ringbuf_reset(&fwd->from_socket) == -1)
		TRACE("ringbuf_reset() failed");
_fail_from_socket:
	if (ringbuf_reset(&fwd->to_socket) == -1)
		TRACE("ringbuf_reset() failed");
_fail_to_socket:
	return -1;
}

int fwd_reset(struct fwd *fwd)
{
	int rc = 0;
	event_free(fwd->sigchld);
	event_free(fwd->socket_write);
	event_free(fwd->socket_read);
	event_free(fwd->stderr);
	event_free(fwd->stdout);
	event_free(fwd->stdin);
	event_base_free(fwd->base);
	if (ringbuf_reset(&fwd->from_socket) == -1) {
		TRACE("ringbuf_reset() failed");
		rc = -1;
	}
	if (ringbuf_reset(&fwd->to_socket) == -1) {
		TRACE("ringbuf_reset() failed");
		rc = -1;
	}
	return rc;
}

int fwd(int socket_fd, int stdin_fd, int stdout_fd, int stderr_fd)
{
	int rc = -1;

	struct fwd fwd;
	if (fwd_init(&fwd, socket_fd, stdin_fd, stdout_fd, stderr_fd) == -1) {
		TRACE("fwd_init() failed");
		goto _out;
	}

	if (event_add(fwd.stdout, NULL) == -1) {
		TRACE("event_add(%p) failed", fwd.stdout);
		goto _out_fwd_reset;
	}

	if (event_add(fwd.stderr, NULL) == -1) {
		TRACE("event_add(%p) failed", fwd.stderr);
		goto _out_fwd_reset;
	}

	if (event_add(fwd.socket_read, NULL) == -1) {
		TRACE("event_add(%p) failed", fwd.socket_read);
		goto _out_fwd_reset;
	}

	if (event_base_dispatch(fwd.base) == -1) {
		TRACE("event_base_dispatch(%p) failed", fwd.base);
		goto _out_fwd_reset;
	}

	rc = 0;

_out_fwd_reset:
	if (fwd_reset(&fwd) == -1)
		TRACE("fwd_reset() failed");
_out:
	return rc;
}

int accept_and_fwd(int server_fd, struct pipes *pipes)
{
	int fd = accept(server_fd, NULL, NULL);
	if (fd == -1) {
		TRACE_ERRNO("accept(%d) failed", server_fd);
		return -1;
	}

	int rc = fwd(fd, pipes->stdin[WRITE_END], pipes->stdout[READ_END], pipes->stderr[READ_END]);

	if (close(fd) == -1)
		TRACE_ERRNO("close(%d) failed", fd);
	return rc;
}

int accept_and_fwd_loop(int server_fd, struct pipes *pipes)
{
	while (1) {
		int rc = accept_and_fwd(server_fd, pipes);
		if (rc == -1) {
			TRACE("accept_and_fwd() failed");
			return -1;
		}
		if (rc == 0)
			return 0;
	}
}

int get_server_fd(const char *guid)
{
	if (guid[0] == 'f' &&
	    guid[1] == 'd' &&
	    guid[2] == '=') {
		return atoi(guid + 3);
	} else {
		struct sockaddr_un sa;
		un_initaddr(&sa, guid);
		return un_listen(&sa);
	}
}

void exec_child(struct pipes *pipes, char **args)
{
	if (handle_pipes_in_child(pipes) == -1) {
		TRACE("handle_pipes_in_child() failed");
		goto _fail;
	}
	if (execvp(args[0], args) == -1) {
		TRACE_ERRNO("execvp(%s) failed", args[0]);
		goto _fail;
	}
_fail:
	_exit(1);
}

int main(int argc, char **argv)
{
	int rc = 1;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s GUID|fd=N PROGRAM [ARG]...\n", argv[0]);
		goto _out;
	}

	int server_fd = get_server_fd(argv[1]);
	if (server_fd == -1) {
		TRACE("get_server_fd(%s) failed", argv[1]);
		goto _out;
	}

	struct pipes pipes;
	if (pipes_init(&pipes) == -1) {
		TRACE("pipes_init() failed");
		goto _out_close_server_fd;
	}

	if (daemon(0, 0) == -1) {
		TRACE_ERRNO("daemon() failed");
		goto _out_reset_pipes;
	}

	if (ignore_signal(SIGHUP) == -1) {
		TRACE_ERRNO("ignore_signal(SIGHUP) failed");
		goto _out_reset_pipes;
	}

	int pid = fork();
	if (pid == -1) {
		TRACE_ERRNO("fork() failed");
		goto _out_reset_pipes;
	}
	if (pid == 0)
		exec_child(&pipes, argv + 2);
	if (handle_pipes_in_parent(&pipes) == -1) {
		TRACE("handle_pipes_in_parent() failed");
		goto _out_reset_pipes;
	}

	if (accept_and_fwd_loop(server_fd, &pipes) == -1) {
		TRACE("accept_and_fwd_loop() failed");
		goto _out_reset_pipes;
	}

	rc = 0;

_out_reset_pipes:
	pipes_reset(&pipes);
_out_close_server_fd:
	if (close(server_fd) == -1)
		TRACE_ERRNO("close(%d) failed", server_fd);
_out:
	return rc;
}
