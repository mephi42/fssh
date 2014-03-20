#define _GNU_SOURCE

#include <errno.h>
#include <event2/event.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "ringbuf.h"

int start_daemon(const struct sockaddr_un *sa, const char *guid, const char *pgm, char **args, size_t arg_count)
{
	int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (server_fd == -1) {
		perror("socket() failed");
		return -1;
	}

	if (bind(server_fd, (const struct sockaddr *)sa, sizeof(*sa)) == -1) {
		perror("bind() failed");
		if (close(server_fd) == -1)
			perror("close() failed");
		return -1;
	}

	if (listen(server_fd, 1) == -1) {
		perror("listen() failed");
		if (close(server_fd) == -1)
			perror("close() failed");
		if (unlink(sa->sun_path) == -1)
			perror("unlink() failed");
		return -1;
	}

	int pid = fork();
	if (pid == -1) {
		perror("fork() failed");
		if (close(server_fd) == -1)
			perror("close() failed");
		if (unlink(sa->sun_path) == -1)
			perror("unlink() failed");
		return -1;
	}
	if (pid == 0) {
		const char **daemon_args = malloc(sizeof(const char *) * (arg_count + 4));
		if (daemon_args == NULL) {
			fprintf(stderr, "malloc() failed\n");
			if (close(server_fd) == -1)
				perror("close() failed");
			if (unlink(sa->sun_path) == -1)
				perror("unlink() failed");
			_exit(1);
		}
		daemon_args[0] = "fssh-daemon";
		daemon_args[1] = guid;
		daemon_args[2] = pgm;
		for (int i = 0; i < arg_count; ++i)
			daemon_args[i + 3] = args[i];
		daemon_args[arg_count + 3] = NULL;
		execvp(daemon_args[0], (char *const *)daemon_args);
		perror("execvp() failed");
		free(daemon_args);
		if (close(server_fd) == -1)
			perror("close() failed");
		if (unlink(sa->sun_path) == -1)
			perror("unlink() failed");
		_exit(1);
	}

	if (close(server_fd) == -1)
		perror("close() failed");
	return pid;
}

int create_session(const char *guid, const char *pgm, char **args, size_t arg_count)
{
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s == -1) {
		perror("socket() failed");
		return -1;
	}

	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "/tmp/fssh-%s", guid);

	if (connect(s, (const struct sockaddr *)&sa, sizeof(sa)) != -1)
		return s;
	if (errno != ENOENT) {
		perror("connect() failed");
		if (close(s) == -1)
			perror("close() failed");
		return -1;
	}

	int daemon_pid = start_daemon(&sa, guid, pgm, args, arg_count);
	if (daemon_pid == -1) {
		fprintf(stderr, "Could not start daemon\n");
		if (close(s) == -1)
			perror("close() failed");
		return -1;
	}

	if (connect(s, (const struct sockaddr *)&sa, sizeof(sa)) != -1)
		return s;
	perror("connect() failed");
	if (kill(daemon_pid, SIGTERM) == -1)
		perror("kill() failed");
	if (close(s) == -1)
		perror("close() failed");
	return -1;
}

struct fwd
{
	int socket_fd;
	int stdin_eof;
	int socket_eof;
	struct ringbuf to_socket;
	struct ringbuf from_socket;
	struct event_base *base;
	struct event *stdin;
	struct event *stdout;
	struct event *socket_read;
	struct event *socket_write;
};

void fwd_break(struct event_base *base)
{
	if (event_base_loopbreak(base) == -1)
		fprintf(stderr, "event_base_loopbreak() failed\n");
}

int fwd_read(int fd, struct ringbuf *rb, int *eof)
{
	size_t max = ringbuf_max_write(rb);
	if (max == 0)
		return 0;
	ssize_t count = read(fd, rb->write, max);
	if (count == -1) {
		if (errno != EAGAIN) {
			perror("read() failed");
			return -1;
		}
		return 0;
	}
	if (count == 0) {
		*eof = 1;
		return 0;
	}
	ringbuf_write(rb, count);
	return 0;
}

int fwd_write(int fd, struct ringbuf *rb)
{
	size_t max = ringbuf_max_read(rb);
	if (max == 0)
		return 0;
	ssize_t count = write(fd, rb->read, max);
	if (count == -1) {
		if (errno != EAGAIN) {
			perror("write() failed");
			return -1;
		}
		return 0;
	}
	ringbuf_read(rb, count);
	return 0;
}

int fwd_read_more(struct ringbuf *rb, struct event *event, int eof)
{
	if (eof || ringbuf_max_write(rb) == 0)
		return 0;
	if (event_add(event, NULL) == -1) {
		fprintf(stderr, "event_add() failed\n");
		return -1;
	}
	return 0;
}

int fwd_write_more(struct ringbuf *rb, struct event *event)
{
	if (ringbuf_max_read(rb) == 0)
		return 0;
	if (event_add(event, NULL) == -1) {
		fprintf(stderr, "event_add() failed\n");
		return -1;
	}
	return 0;
}

void on_stdin(int fd, short events, void *arg)
{
	struct fwd *fwd = arg;
	struct ringbuf* rb = &fwd->to_socket;
	if (fwd_read(0, rb, &fwd->stdin_eof) == -1 ||
	    fwd_write(fwd->socket_fd, rb) == -1 ||
	    fwd_read_more(rb, fwd->stdin, fwd->stdin_eof) == -1 ||
	    fwd_write_more(rb, fwd->socket_write) == -1) {
		fwd_break(fwd->base);
	}
}

void on_stdout(int fd, short events, void *arg)
{
	struct fwd *fwd = arg;
	struct ringbuf *rb = &fwd->from_socket;
	if (fwd_write(1, rb) == -1 ||
	    fwd_read(fwd->socket_fd, rb, &fwd->socket_eof) == -1 ||
	    fwd_read_more(rb, fwd->socket_read, fwd->socket_eof) == -1 ||
	    fwd_write_more(rb, fwd->stdout) == -1) {
		fwd_break(fwd->base);
	}
}

void on_socket_read(int fd, short events, void *arg)
{
	struct fwd *fwd = arg;
	struct ringbuf* rb = &fwd->from_socket;
	if (fwd_read(fwd->socket_fd, rb, &fwd->socket_eof) == -1 ||
	    fwd_write(1, rb) == -1 ||
	    fwd_read_more(rb, fwd->socket_read, fwd->socket_eof) == -1 ||
	    fwd_write_more(rb, fwd->stdout) == -1) {
		fwd_break(fwd->base);
	}
}

void on_socket_write(int fd, short events, void *arg)
{
	struct fwd *fwd = arg;
	struct ringbuf *rb = &fwd->to_socket;
	if (fwd_write(fwd->socket_fd, rb) == -1 ||
	    fwd_read(0, rb, &fwd->stdin_eof) == -1 ||
	    fwd_read_more(rb, fwd->stdin, fwd->stdin_eof) == -1 ||
	    fwd_write_more(rb, fwd->socket_write) == -1) {
		fwd_break(fwd->base);
	}
}

int fwd_init(struct fwd *fwd, int socket_fd)
{
	fwd->socket_fd = socket_fd;
	fwd->stdin_eof = 0;
	fwd->socket_eof = 0;

	if (ringbuf_init(&fwd->to_socket, 4096) == -1) {
		fprintf(stderr, "ringbuf_init() failed\n");
		goto _fail_to_socket;
	}

	if (ringbuf_init(&fwd->from_socket, 4096) == -1) {
		fprintf(stderr, "ringbuf_init() failed\n");
		goto _fail_from_socket;
	}

	fwd->base = event_base_new();
	if (fwd->base == NULL) {
		fprintf(stderr, "event_base_new() failed\n");
		goto _fail_base;
	}

	fwd->stdin = event_new(fwd->base, 0, EV_READ, &on_stdin, fwd);
	if (fwd->stdin == NULL) {
		fprintf(stderr, "event_new() failed\n");
		goto _fail_stdin;
	}

	fwd->stdout = event_new(fwd->base, 1, EV_WRITE, &on_stdout, fwd);
	if (fwd->stdout == NULL) {
		fprintf(stderr, "event_new() failed\n");
		goto _fail_stdout;
	}

	fwd->socket_read = event_new(fwd->base, fwd->socket_fd, EV_READ, &on_socket_read, fwd);
	if (fwd->socket_read == NULL) {
		fprintf(stderr, "event_new() failed\n");
		goto _fail_socket_read;
	}

	fwd->socket_write = event_new(fwd->base, fwd->socket_fd, EV_WRITE, &on_socket_write, fwd);
	if (fwd->socket_write == NULL) {
		fprintf(stderr, "event_new() failed\n");
		goto _fail_socket_write;
	}

	return 0;

_fail_socket_write:
	event_free(fwd->socket_read);
_fail_socket_read:
	event_free(fwd->stdout);
_fail_stdout:
	event_free(fwd->stdin);
_fail_stdin:
	event_base_free(fwd->base);
_fail_base:
	ringbuf_reset(&fwd->from_socket);
_fail_from_socket:
	ringbuf_reset(&fwd->to_socket);
_fail_to_socket:
	return -1;
}

void fwd_reset(struct fwd *fwd)
{
	event_free(fwd->socket_write);
	event_free(fwd->socket_read);
	event_free(fwd->stdout);
	event_free(fwd->stdin);
	event_base_free(fwd->base);
	ringbuf_reset(&fwd->from_socket);
	ringbuf_reset(&fwd->to_socket);
}

int do_fwd(int socket_fd)
{
	struct fwd fwd;
	if (fwd_init(&fwd, socket_fd) == -1) {
		fprintf(stderr, "fwd_init() failed\n");
		return -1;
	}

	if (event_add(fwd.stdin, NULL) == -1) {
		fprintf(stderr, "event_add() failed\n");
		fwd_reset(&fwd);
		return -1;
	}

	if (event_add(fwd.socket_read, NULL) == -1) {
		fprintf(stderr, "event_add() failed\n");
		fwd_reset(&fwd);
		return -1;
	}

	if (event_base_dispatch(fwd.base) == -1) {
		fprintf(stderr, "event_base_dispatch() failed\n");
		fwd_reset(&fwd);
		return -1;
	}

	fwd_reset(&fwd);
	return 0;
}

int make_nonblocking(int fd) {
	int flags = fcntl(fd, F_GETFD);
	if (flags == -1) {
		perror("fcntl() failed");
		return -1;
	}
	if (fcntl(fd, F_SETFD, flags | O_NONBLOCK) == -1) {
		perror("fcntl() failed");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "Usage: %s GUID PROGRAM [ARG]...\n", argv[0]);
		return 1;
	}

	int socket_fd = create_session(argv[1], argv[2], argv + 3, argc - 3);
	if (socket_fd == -1) {
		fprintf(stderr, "Could not create session\n");
		return 1;
	}

	if (make_nonblocking(0) == -1 ||
	    make_nonblocking(1) == -1 ||
	    make_nonblocking(socket_fd) == -1) {
		fprintf(stderr, "make_nonblocking() failed\n");
		if (close(socket_fd) == -1)
			perror("close() failed");
		return 1;
	}

	if (do_fwd(socket_fd) == -1) {
		fprintf(stderr, "do_fwd() failed\n");
		if (close(socket_fd) == -1)
			perror("close() failed");
		return 1;
	}

	if (close(socket_fd) == -1)
		perror("close() failed");
	return 0;
}
