#ifndef FSSH_CHILD_H
#define FSSH_CHILD_H

#include <signal.h>

struct child_pipes {
	int stdin_pipe[2];
	int stdout_pipe[2];
	int stderr_pipe[2];
};

struct child {
	struct child_pipes pipes;
	sigset_t sigchld;
	int sigchld_fd;
	pid_t pid;
};

int child_init(struct child *c, char **argv);
int child_reset(struct child *c);

#endif
