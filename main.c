#define _GNU_SOURCE

#include "reset.h"
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <stdio.h>
#include "trace.h"
#include <unistd.h>

__attribute__((noreturn)) static void exec_socat(char **argv)
{
	int fd = STDIN_FILENO;
	if (reset_fd(&fd) == -1)
		goto _fail;
	fd = STDOUT_FILENO;
	if (reset_fd(&fd) == -1)
		goto _fail;

	if (execvp(argv[0], argv) == -1) {
		TRACE_ERRNO("exec(%s) failed", argv[0]);
		goto _fail;
	}
_fail:
	_exit(1);
}

static pid_t fork_socat(sigset_t *sigchld, char **argv)
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
		exec_socat(argv);
	}
	TRACE("forked ssh, pid=%i", pid);
	return pid;
}

__attribute__((noreturn)) static void exec_client()
{
	char *args[3];
	args[0] = "fssh-client";
	args[1] = "ipc:///tmp/fssh-client";
	args[2] = NULL;
	if (execvp(args[0], args) == -1)
		TRACE_ERRNO("exec(%s) failed", args[0]);
	_exit(1);
}

static pid_t fork_client(sigset_t *sigchld)
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
		exec_client();
	}
	TRACE("forked fssh-client, pid=%i", pid);
	return pid;
}

static int get_nonopt_index(int argn, int argc, char **argv)
{
	for (int i = argn; i < argc; ++i)
		if (argv[i][0] != '-')
			return i;
	return -1;
}

static int get_pgm_index(int argc, char **argv)
{
	int hostname_index = get_nonopt_index(0, argc, argv);
	if (hostname_index == -1)
		return -1;
	return get_nonopt_index(hostname_index + 1, argc, argv);
}

struct sbuf {
	char *s;
	size_t size;
	size_t pos;
};

static int sbuf_init(struct sbuf *sbuf, size_t size)
{
	sbuf->s = malloc(size);
	if (sbuf->s == NULL) {
		TRACE("malloc(%zu) failed", size);
		return -1;
	}
	sbuf->size = size;
	sbuf->pos = 0;
	sbuf->s[sbuf->pos] = 0;
	return 0;
}

static void sbuf_reset(struct sbuf *sbuf)
{
	free(sbuf->s);
}

static int sbuf_ensure_capacity(struct sbuf *sbuf, size_t capacity)
{
	while (capacity >= sbuf->size) {
		char *orig = sbuf->s;
		sbuf->s = realloc(sbuf->s, sbuf->size * 2);
		if (sbuf->s == orig) {
			TRACE("realloc(%zu) failed", sbuf->size * 2);
			return -1;
		}
		sbuf->size *= 2;
	}
	return 0;
}

static int sbuf_append(struct sbuf *sbuf, const char *s, size_t n)
{
	if (sbuf_ensure_capacity(sbuf, sbuf->pos + n) == -1)
		return -1;
	memcpy(sbuf->s + sbuf->pos, s, n);
	sbuf->pos += n;
	sbuf->s[sbuf->pos] = 0;
	return 0;
}

static int sbuf_append_string(struct sbuf *sbuf, const char *s)
{
	return sbuf_append(sbuf, s, strlen(s));
}

static const char* find_special_char(const char *s)
{
	for (; ; ++s) {
		switch (*s) {
		case 0:
		case '\\': case '\'': case '"':
		case '(': case ')':
		case '[': case ']':
		case '{': case '}':
		case ' ': case ',': case ':':
			return s;
		}
	}
}

static int append_exec_arg(struct sbuf *exec_arg, const char *s)
{
	char space = ' ';
	if (sbuf_append(exec_arg, &space, sizeof(space)) == -1)
		return -1;

	const char *current = s;
	while (1) {
		const char *next = find_special_char(current);
		if (next != current)
			if (sbuf_append(exec_arg, current, next - current) == -1)
				return -1;
		if (*next == 0)
			return 0;
		char c[2];
		c[0] = '\\';
		c[1] = *next;
		if (sbuf_append(exec_arg, c, sizeof(c)) == -1)
			return -1;
		current = next + 1;
	}
}

static int init_exec_arg(struct sbuf *exec_arg, int argc, char **argv)
{
	int pgm_index = get_pgm_index(argc, argv);
	if (pgm_index == -1) {
		fprintf(stderr, "Usage: %s [SSH_OPTIONS] [USER@]HOSTNAME PGM [ARGS]...\n", argv[0]);
		goto _fail;
	}

	if (sbuf_init(exec_arg, 1024) == -1)
		goto _fail;
	if (sbuf_append_string(exec_arg, "EXEC:ssh") == -1)
		goto _fail_reset;

	int argv_index = 0;
	while (argv_index < pgm_index)
		if (append_exec_arg(exec_arg, argv[argv_index++]) == -1)
			goto _fail_reset;
	if (append_exec_arg(exec_arg, "fssh-fwd") == -1)
		goto _fail_reset;
	if (append_exec_arg(exec_arg, "UNIX-CONNECT:/tmp/fssh-server,retry=3") == -1)
		goto _fail_reset;
	if (append_exec_arg(exec_arg, "ipc:///tmp/fssh-server") == -1)
		goto _fail_reset;
	while (argv_index < argc)
		if (append_exec_arg(exec_arg, argv[argv_index++]) == -1)
			goto _fail_reset;

	TRACE("init_exec_arg() = %s", exec_arg->s);

	return 0;

_fail_reset:
	sbuf_reset(exec_arg);
_fail:
	return -1;
}

int terminate_process(pid_t pid)
{
	int rc = -1;
	if (kill(pid, SIGKILL) == -1) {
		TRACE_ERRNO("kill(%i) failed", pid);
		goto _out;
	}
	int status;
	if (waitpid(pid, &status, 0) == -1) {
		TRACE_ERRNO("waitpid(%i) failed", pid);
		goto _out;
	}
	rc = 0;
_out:
	return rc;
}

int main(int argc, char **argv)
{
	int rc = 1;

	char *args[4];
	args[0] = "socat";
	args[1] = "UNIX-LISTEN:/tmp/fssh-client,unlink-early";
	struct sbuf exec_arg;
	if (init_exec_arg(&exec_arg, argc - 1, argv + 1) == -1)
		goto _out;
	args[2] = exec_arg.s;
	args[3] = NULL;

        sigset_t sigchld;
        if (sigemptyset(&sigchld) == -1) {
                TRACE_ERRNO("sigemptyset() failed");
                goto _out_free_exec_arg;
        }
        if (sigaddset(&sigchld, SIGCHLD) == -1) {
                TRACE_ERRNO("sigaddset() failed");
                goto _out_free_exec_arg;
        }
        if (sigprocmask(SIG_BLOCK, &sigchld, NULL) == -1) {
                TRACE_ERRNO("sigprocmask() failed");
                goto _out_free_exec_arg;
        }
        int sigchld_fd = signalfd(-1, &sigchld, SFD_CLOEXEC);
        if (sigchld_fd == -1) {
                TRACE_ERRNO("signalfd() failed");
                goto _out_free_exec_arg;
        }

	pid_t socat_pid = fork_socat(&sigchld, args);
	if (socat_pid == -1)
		goto _out_close_sigchld_fd;

	pid_t client_pid = fork_client(&sigchld);
	if (client_pid == -1)
		goto _out_kill;

	while (1) {
		struct signalfd_siginfo si;
		ssize_t count = read(sigchld_fd, &si, sizeof(si));
		if (count == -1) {
			TRACE_ERRNO("read() failed");
			goto _out_kill;
		}
		TRACE("signal received: signo=%i", si.ssi_signo);
		while (1) {
			int status;
			pid_t pid = waitpid(-1, &status, WNOHANG);
			if (pid == -1) {
				TRACE_ERRNO("waitpid() failed");
				goto _out_kill;
			}
			if (pid == 0)
				break;
			TRACE("pid=%i", pid);
			if (pid == client_pid) {
				if (WIFEXITED(status))
					rc = WEXITSTATUS(status);
				else
					rc = 1;
				goto _out_kill;
			}
			if (pid == socat_pid) {
				socat_pid = fork_socat(&sigchld, args);
				if (socat_pid == -1)
					goto _out_kill;
			}
		}
	}

_out_kill:
	if (socat_pid != -1)
		terminate_process(socat_pid);
	if (client_pid != -1)
		terminate_process(client_pid);

_out_close_sigchld_fd:
	if (close(sigchld_fd) == -1)
		TRACE_ERRNO("close(%i) failed", sigchld_fd);

_out_free_exec_arg:
	sbuf_reset(&exec_arg);

_out:
	return rc;
}
