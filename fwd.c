#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "trace.h"
#include <unistd.h>

__attribute__((noreturn)) static void exec_daemon(int argc, char **argv)
{
	char *args[argc + 2];
	args[0] = "fssh-daemon";
	memcpy(&args[1], argv, argc * sizeof(char *));
	args[argc + 1] = NULL;

	if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) {
		TRACE_ERRNO("signal(SIGCHLD, SIG_DFL) failed");
		goto _fail;
	}

	if (daemon(0, 0) == -1) {
		TRACE_ERRNO("daemon() failed");
		goto _fail;
	}

	TRACE("exec fssh-daemon, pid=%i", getpid());
	if (execvp(args[0], args) == -1) {
		TRACE_ERRNO("execvp(%s) failed", args[0]);
		goto _fail;
	}

_fail:
	_exit(1);
}

static pid_t fork_daemon(int argc, char **argv)
{
	pid_t pid = fork();
	if (pid == -1) {
		TRACE_ERRNO("fork() failed");
		goto _out;
	}

	if (pid == 0)
		exec_daemon(argc, argv);

_out:
	return pid;
}

__attribute__((noreturn)) static void exec_socat(char *address)
{
	char *args[4];
	args[0] = "socat";
	args[1] = "TCP-LISTEN:32168,reuseaddr";
	args[2] = address;
	args[3] = NULL;

	TRACE("exec socat, pid=%i", getpid());
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

	if (argc < 4) {
		fprintf(stderr, "Usage: %s SOCAT_ADDRESS ZEROMQ_ENDPOINT PGM [ARGS]...\n", argv[0]);
		goto _out;
	}

	if (sigignore(SIGCHLD) == -1) {
		TRACE_ERRNO("sigignore(SIGCHLD) failed");
		goto _out;
	}

	if (fork_daemon(argc - 2, argv + 2) == -1)
		goto _out;

	exec_socat(argv[1]);

_out:
	return rc;
}
