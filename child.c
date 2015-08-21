#define _GNU_SOURCE

#include "child.h"
#include <sys/signalfd.h>
#include "trace.h"
#include <unistd.h>

static int child_pipes_init(struct child_pipes *p)
{
	if (pipe(p->stdin_pipe) == -1) {
		TRACE_ERRNO("pipe(stdin) failed");
		goto _fail;
	}
	TRACE("stdin=(r=%i, w=%i)", p->stdin_pipe[0], p->stdin_pipe[1]);

	if (pipe(p->stdout_pipe) == -1) {
		TRACE_ERRNO("pipe(stdout) failed");
		goto _fail_cleanup_stdin;
	}
	TRACE("stdout=(r=%i, w=%i)", p->stdout_pipe[0], p->stdout_pipe[1]);

	if (pipe(p->stderr_pipe) == -1) {
		TRACE_ERRNO("pipe(stderr) failed");
		goto _fail_cleanup_stdout;
	}
	TRACE("stderr=(r=%i, w=%i)", p->stderr_pipe[0], p->stderr_pipe[1]);

	return 0;

_fail_cleanup_stdout:
	if (close(p->stdout_pipe[0]) == -1)
		TRACE_ERRNO("close(%i) failed", p->stdout_pipe[0]);
	if (close(p->stdout_pipe[1]) == -1)
		TRACE_ERRNO("close(%i) failed", p->stdout_pipe[1]);
_fail_cleanup_stdin:
	if (close(p->stdin_pipe[0]) == -1)
		TRACE_ERRNO("close(%i) failed", p->stdin_pipe[0]);
	if (close(p->stdin_pipe[1]) == -1)
		TRACE_ERRNO("close(%i) failed", p->stdin_pipe[1]);
_fail:
	return -1;
}

static int fd_reset(int fd, const char *label)
{
	if (fd != -1 && close(fd) == -1) {
		TRACE_ERRNO("close(%s=%i) failed", label, fd);
		return -1;
	}
	return 0;
}

static int child_pipes_reset(struct child_pipes *p)
{
	int rc = 0;
	rc |= fd_reset(p->stderr_pipe[0], "stderr read");
	rc |= fd_reset(p->stderr_pipe[1], "stderr write");
	rc |= fd_reset(p->stdout_pipe[0], "stdout read");
	rc |= fd_reset(p->stdout_pipe[1], "stdout write");
	rc |= fd_reset(p->stdin_pipe[0], "stdin read");
	rc |= fd_reset(p->stdin_pipe[1], "stdin write");
	return rc;
}

__attribute__((noreturn)) static void child_exec(char **argv, struct child_pipes *p)
{
	if (dup2(p->stdin_pipe[0], STDIN_FILENO) == -1) {
		TRACE_ERRNO("dup2(stdin read=%i, %i) failed", p->stdin_pipe[0], STDIN_FILENO);
		goto _fail;
	}
	if (close(p->stdin_pipe[0]) == -1)
		TRACE_ERRNO("close(stdin read=%i) failed", p->stdin_pipe[0]);
	if (close(p->stdin_pipe[1]) == -1)
		TRACE_ERRNO("close(stdin write=%i) failed", p->stdin_pipe[1]);

	if (dup2(p->stdout_pipe[1], STDOUT_FILENO) == -1) {
		TRACE_ERRNO("dup2(stdout write=%i, %i) failed", p->stdout_pipe[1], STDOUT_FILENO);
		goto _fail;
	}
	if (close(p->stdout_pipe[0]) == -1)
		TRACE_ERRNO("close(stdout read=%i) failed", p->stdout_pipe[0]);
	if (close(p->stdout_pipe[1]) == -1)
		TRACE_ERRNO("close(stdout write=%i) failed", p->stdout_pipe[1]);

	if (dup2(p->stderr_pipe[1], STDERR_FILENO) == -1) {
		TRACE_ERRNO("dup2(stderr write=%i, %i) failed", p->stderr_pipe[1], STDERR_FILENO);
		goto _fail;
	}
	if (close(p->stderr_pipe[0]) == -1)
		TRACE_ERRNO("close(stderr read=%i) failed", p->stderr_pipe[0]);
	if (close(p->stderr_pipe[1]) == -1)
		TRACE_ERRNO("close(stderr write=%i) failed", p->stderr_pipe[1]);

	if (execvp(argv[0], argv) == -1) {
		TRACE_ERRNO("execvp(%s) failed", argv[0]);
		goto _fail;
	}

_fail:
	_exit(1);
}

static pid_t child_fork(char **argv, struct child_pipes *pipes, sigset_t *sigchld)
{
	pid_t pid = fork();
	if (pid == -1) {
		TRACE_ERRNO("fork() failed");
		return -1;
	}
	if (pid == 0) {
		if (sigprocmask(SIG_UNBLOCK, sigchld, NULL) == -1) {
			TRACE_ERRNO("sigprocmask() failed");
			_exit(1);
		}
		child_exec(argv, pipes);
	}
	return pid;
}

int child_init(struct child *c, char **argv)
{
	if (child_pipes_init(&c->pipes) == -1) {
		TRACE("child_pipes_init() failed");
		goto _fail;
	}

	if (sigemptyset(&c->sigchld) == -1) {
		TRACE_ERRNO("sigemptyset() failed");
		goto _fail_cleanup_pipes;
	}
	if (sigaddset(&c->sigchld, SIGCHLD) == -1) {
		TRACE_ERRNO("sigaddset() failed");
		goto _fail_cleanup_pipes;
	}
	if (sigprocmask(SIG_BLOCK, &c->sigchld, NULL) == -1) {
		TRACE_ERRNO("sigprocmask() failed");
		goto _fail_cleanup_pipes;
	}
	c->sigchld_fd = signalfd(-1, &c->sigchld, SFD_NONBLOCK | SFD_CLOEXEC);
	if (c->sigchld_fd == -1) {
		TRACE_ERRNO("signalfd() failed");
		goto _fail_cleanup_sigchld;
	}

	c->pid = child_fork(argv, &c->pipes, &c->sigchld);
	if (c->pid == -1) {
		TRACE_ERRNO("fork() failed");
		goto _fail_cleanup_sigchld_fd;
	}

	return 0;

_fail_cleanup_sigchld_fd:
	if (close(c->sigchld_fd) == -1)
		TRACE_ERRNO("close(%d) failed", c->sigchld_fd);
_fail_cleanup_sigchld:
	if (sigprocmask(SIG_UNBLOCK, &c->sigchld, NULL) == -1)
		TRACE_ERRNO("sigprocmask() failed");
_fail_cleanup_pipes:
	if (child_pipes_reset(&c->pipes) == -1)
		TRACE("child_pipes_reset() failed");
_fail:
	return -1;
}

int child_reset(struct child *c)
{
	int rc = 0;
	rc |= fd_reset(c->sigchld_fd, "sigchld");
	if (sigprocmask(SIG_UNBLOCK, &c->sigchld, NULL) == -1) {
		TRACE_ERRNO("sigprocmask() failed");
		rc = -1;
	}
	if (child_pipes_reset(&c->pipes) == -1) {
		TRACE("child_pipes_reset() failed");
		rc = -1;
	}
	return rc;
}
