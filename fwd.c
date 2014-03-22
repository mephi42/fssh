#define _GNU_SOURCE

#include <errno.h>
#include <event2/event.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "nonblock.h"
#include "ringbuf.h"
#include "trace.h"
#include "un.h"

int start_daemon(const struct sockaddr_un *sa, const char *pgm, char **args, size_t arg_count)
{
	int server_fd = un_listen(sa);
	if (server_fd == -1) {
		TRACE("un_listen() failed");
		goto _fail_listen;
	}
	int pid = fork();
	if (pid == -1) {
		TRACE_ERRNO("fork() failed");
		goto _fail_fork;
	}
	if (pid == 0) {
		const char *daemon_args[arg_count + 4];
		daemon_args[0] = "fssh-daemon";
		char fdarg[16];
		snprintf(fdarg, sizeof(fdarg), "fd=%d", server_fd);
		daemon_args[1] = fdarg;
		daemon_args[2] = pgm;
		for (int i = 0; i < arg_count; ++i)
			daemon_args[i + 3] = args[i];
		daemon_args[arg_count + 3] = NULL;
		if (execvp(daemon_args[0], (char *const *)daemon_args) == -1)
			TRACE_ERRNO("execvp(%s) failed", daemon_args[0]);
		if (close(server_fd) == -1)
			TRACE_ERRNO("close(%d) failed", server_fd);
		if (unlink(sa->sun_path) == -1)
			TRACE_ERRNO("unlink(%s) failed", sa->sun_path);
		_exit(1);
	}

	if (close(server_fd) == -1)
		TRACE_ERRNO("close(%d) failed", server_fd);
	return pid;

_fail_fork:
	if (close(server_fd) == -1)
		TRACE_ERRNO("close(%d) failed", server_fd);
	if (unlink(sa->sun_path) == -1)
		TRACE_ERRNO("unlink(%s) failed", sa->sun_path);
_fail_listen:
	return -1;
}

int create_session(const char *guid, const char *pgm, char **args, size_t arg_count)
{
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s == -1) {
		TRACE_ERRNO("socket() failed");
		goto _fail_socket;
	}

	struct sockaddr_un sa;
	un_initaddr(&sa, guid);

	if (connect(s, (const struct sockaddr *)&sa, sizeof(sa)) != -1)
		goto _out;
	if (errno != ENOENT) {
		TRACE_ERRNO("connect(%d) failed", s);
		goto _fail_connect1;
	}

	int daemon_pid = start_daemon(&sa, pgm, args, arg_count);
	if (daemon_pid == -1) {
		TRACE("start_daemon() failed");
		goto _fail_start_daemon;
	}

	if (connect(s, (const struct sockaddr *)&sa, sizeof(sa)) == -1) {
		TRACE_ERRNO("connect(%d) failed", s);
		goto _fail_connect2;
	}

_out:
	return s;

_fail_connect2:
_fail_start_daemon:
_fail_connect1:
	if (close(s) == -1)
		TRACE_ERRNO("close(%d) failed", s);
_fail_socket:
	return -1;
}

struct fwd_oneway {
	int src_fd;
	int dst_fd;
	int eof;
	struct ringbuf buf;
	struct event *src_event;
	struct event *dst_event;
};

struct fwd {
	struct event_base *base;
	struct fwd_oneway from_socket;
	struct fwd_oneway to_socket;
};

void fwd_break(struct event_base *base)
{
	if (event_base_loopbreak(base) == -1)
		TRACE("event_base_loopbreak(%p) failed", base);
}

int fwd_read(struct fwd_oneway *fwd)
{
	size_t max = ringbuf_max_write(&fwd->buf);
	if (max == 0)
		return 0;
	ssize_t count = read(fwd->src_fd, fwd->buf.write, max);
	if (count == -1) {
		if (errno == EAGAIN)
			return 0;
		TRACE_ERRNO("read(%d, %d) failed", fwd->src_fd, max);
		return -1;
	}
	if (count == 0) {
		fwd->eof = 1;
		return 0;
	}
	ringbuf_write(&fwd->buf, count);
	return 0;
}

int fwd_write(struct fwd_oneway *fwd)
{
	size_t max = ringbuf_max_read(&fwd->buf);
	if (max == 0)
		return 0;
	ssize_t count = write(fwd->dst_fd, fwd->buf.read, max);
	if (count == -1) {
		if (errno == EAGAIN)
			return 0;
		TRACE_ERRNO("write(%d, %d) failed", fwd->dst_fd, max);
		return -1;
	}
	ringbuf_read(&fwd->buf, count);
	return 0;
}

int fwd_read_more(struct fwd_oneway *fwd)
{
	if (fwd->eof || ringbuf_max_write(&fwd->buf) == 0)
		return 0;
	if (event_add(fwd->src_event, NULL) == -1) {
		TRACE("event_add(%p) failed", fwd->src_event);
		return -1;
	}
	return 0;
}

int fwd_write_more(struct fwd_oneway *fwd)
{
	if (ringbuf_max_read(&fwd->buf) == 0)
		return 0;
	if (event_add(fwd->dst_event, NULL) == -1) {
		TRACE("event_add(%p) failed", fwd->dst_event);
		return -1;
	}
	return 0;
}

void on_src(int fd, short events, void *arg)
{
	struct fwd_oneway *fwd = arg;
	if (fwd_read(fwd) == -1) {
		TRACE("fwd_read(%p) failed", fwd);
		goto _fail;
	}
	if (fwd_write(fwd) == -1) {
		TRACE("fwd_write(%p) failed", fwd);
		goto _fail;
	}
	if (fwd_read_more(fwd) == -1) {
		TRACE("fwd_read_more(%p) failed", fwd);
		goto _fail;
	}
	if (fwd_write_more(fwd) == -1) {
		TRACE("fwd_write_more(%p) failed", fwd);
		goto _fail;
	}
	return;

_fail:
	fwd_break(event_get_base(fwd->src_event));
}

void on_dst(int fd, short events, void *arg)
{
	struct fwd_oneway *fwd = arg;
	if (fwd_write(fwd) == -1) {
		TRACE("fwd_write(%p) failed", fwd);
		goto _fail;
	}
	if (fwd_read(fwd) == -1) {
		TRACE("fwd_read(%p) failed", fwd);
		goto _fail;
	}
	if (fwd_read_more(fwd) == -1) {
		TRACE("fwd_read_more(%p) failed", fwd);
		goto _fail;
	}
	if (fwd_write_more(fwd) == -1) {
		TRACE("fwd_write_more(%p) failed", fwd);
		goto _fail;
	}
	return;

_fail:
	fwd_break(event_get_base(fwd->dst_event));
}

int fwd_oneway_init(struct fwd_oneway *fwd, struct event_base *base, int src_fd, int dst_fd)
{
	fwd->src_fd = src_fd;
	fwd->dst_fd = dst_fd;
	fwd->eof = 0;
	if (ringbuf_init(&fwd->buf, 4096) == -1) {
		TRACE("ringbuf_init() failed");
		goto _fail_ringbuf;
	}

	fwd->src_event = event_new(base, src_fd, EV_READ, &on_src, fwd);
	if (fwd->src_event == NULL) {
		TRACE("event_new() failed");
		goto _fail_src;
	}

	fwd->dst_event = event_new(base, dst_fd, EV_WRITE, &on_dst, fwd);
	if (fwd->dst_event == NULL) {
		TRACE("event_new() failed");
		goto _fail_dst;
	}

	return 0;

_fail_dst:
	event_free(fwd->src_event);
_fail_src:
	if (ringbuf_reset(&fwd->buf) == -1)
		TRACE("ringbuf_reset() failed");
_fail_ringbuf:
	return -1;
}

int fwd_oneway_reset(struct fwd_oneway *fwd)
{
	int rc = 0;
	event_free(fwd->dst_event);
	event_free(fwd->src_event);
	if (ringbuf_reset(&fwd->buf) == -1) {
		TRACE("ringbuf_reset() failed");
		rc = -1;
	}
	return rc;
}

int fwd_init(struct fwd *fwd, int socket_fd)
{
	fwd->base = event_base_new();
	if (fwd->base == NULL) {
		TRACE("event_base_new() failed");
		goto _fail_base;
	}

	if (fwd_oneway_init(&fwd->to_socket, fwd->base, 0, socket_fd) == -1) {
		TRACE("fwd_oneway_init() failed");
		goto _fail_to_socket;
	}

	if (fwd_oneway_init(&fwd->from_socket, fwd->base, socket_fd, 1) == -1) {
		TRACE("fwd_oneway_init() failed");
		goto _fail_from_socket;
	}

	return 0;

_fail_from_socket:
	if (fwd_oneway_reset(&fwd->to_socket) == -1)
		TRACE("fwd_oneway_reset() failed");
_fail_to_socket:
	event_base_free(fwd->base);
_fail_base:
	return -1;
}

int fwd_reset(struct fwd *fwd)
{
	int rc = 0;

	if (fwd_oneway_reset(&fwd->from_socket) == -1) {
		TRACE("fwd_oneway_reset() failed");
		rc = -1;
	}

	if (fwd_oneway_reset(&fwd->to_socket) == -1) {
		TRACE("fwd_oneway_reset() failed");
		rc = -1;
	}

	event_base_free(fwd->base);

	return rc;
}

int fwd(int socket_fd)
{
	int rc = -1;

	if (make_nonblocking(0) == -1 ||
	    make_nonblocking(1) == -1 ||
	    make_nonblocking(socket_fd) == -1) {
		TRACE("make_nonblocking() failed");
		goto _out;
	}

	struct fwd fwd;
	if (fwd_init(&fwd, socket_fd) == -1) {
		TRACE("fwd_init() failed");
		goto _out;
	}

	if (event_add(fwd.to_socket.src_event, NULL) == -1) {
		TRACE("event_add(%p) failed", fwd.to_socket.src_event);
		goto _out_fwd_reset;
	}

	if (event_add(fwd.from_socket.src_event, NULL) == -1) {
		TRACE("event_add(%p) failed", fwd.from_socket.src_event);
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

int main(int argc, char **argv)
{
	int rc = 1;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s GUID PROGRAM [ARG]...\n", argv[0]);
		goto _out;
	}

	int socket_fd = create_session(argv[1], argv[2], argv + 3, argc - 3);
	if (socket_fd == -1) {
		TRACE("create_session() failed");
		goto _out;
	}

	if (fwd(socket_fd) == -1) {
		TRACE("fwd() failed");
		goto _out_close_socket_fd;
	}

	rc = 0;

_out_close_socket_fd:
	if (close(socket_fd) == -1)
		TRACE_ERRNO("close(%d) failed", socket_fd);
_out:
	return rc;
}
