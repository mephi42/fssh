#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "trace.h"
#include <unistd.h>

__attribute__((noreturn)) void execute(int argc, char **argv)
{
	char *args[argc + 2];
	args[0] = "fssh-daemon";
	memcpy(&args[1], argv, argc * sizeof(char *));
	args[argc + 1] = NULL;

	if (daemon(0, 0) == -1) {
		TRACE_ERRNO("daemon() failed");
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
		fprintf(stderr, "Usage: %s ZEROMQ_ENDPOINT PGM [ARGS]...\n", argv[0]);
		goto _out;
	}

	pid_t pid = fork();
	if (pid == -1) {
		TRACE_ERRNO("fork() failed");
		goto _out;
	}

	if (pid == 0)
		execute(argc - 1, argv + 1);

	if (sigignore(SIGCHLD) == -1) {
		TRACE_ERRNO("sigignore() failed");
		goto _out;
	}

	sigset_t all;
	if (sigfillset(&all) == -1) {
		TRACE_ERRNO("sigfillset() failed");
		goto _out;
	}
	if (sigdelset(&all, SIGINT)) {
		TRACE_ERRNO("sigdelset() failed");
		goto _out;
	}
	if (sigdelset(&all, SIGTERM)) {
		TRACE_ERRNO("sigdelset() failed");
		goto _out;
	}
	if (sigsuspend(&all) == -1 && errno != EINTR) {
		TRACE_ERRNO("sigsuspend() failed");
		goto _out;
	}

	rc = 0;

_out:
	return rc;
}
