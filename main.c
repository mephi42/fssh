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

__attribute__((noreturn)) static void exec_ssh(char **argv)
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

static pid_t fork_ssh(sigset_t *sigchld, char **argv)
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
		exec_ssh(argv);
	}
	TRACE("forked ssh, pid=%i", pid);
	return pid;
}

__attribute__((noreturn)) static void exec_client()
{
	char *args[3];
	args[0] = "fssh-client";
	args[1] = "tcp://127.0.0.1:32167";
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
	int hostname_index = get_nonopt_index(1, argc, argv);
	if (hostname_index == -1)
		return -1;
	return get_nonopt_index(hostname_index + 1, argc, argv);
}

int main(int argc, char **argv)
{
	int rc = 1;

	char *args[argc + 5];
	int pgm_index = get_pgm_index(argc, argv);
	if (pgm_index == -1) {
		fprintf(stderr, "Usage: %s [SSH_OPTIONS] [USER@]HOSTNAME PGM [ARGS]...\n", argv[0]);
		goto _out;
	}
	int args_index = 0;
	args[args_index++] = "ssh";
	args[args_index++] = "-L";
	args[args_index++] = "localhost:32167:localhost:32168";
	int argv_index = 1;
	while (argv_index < pgm_index)
		args[args_index++] = argv[argv_index++];
	args[args_index++] = "fssh-fwd";
	args[args_index++] = "tcp://127.0.0.1:32168";
	while (argv_index < argc)
		args[args_index++] = argv[argv_index++];
	args[args_index++] = NULL;

        sigset_t sigchld;
        if (sigemptyset(&sigchld) == -1) {
                TRACE_ERRNO("sigemptyset() failed");
                goto _out;
        }
        if (sigaddset(&sigchld, SIGCHLD) == -1) {
                TRACE_ERRNO("sigaddset() failed");
                goto _out;
        }
        if (sigprocmask(SIG_BLOCK, &sigchld, NULL) == -1) {
                TRACE_ERRNO("sigprocmask() failed");
                goto _out;
        }
        int sigchld_fd = signalfd(-1, &sigchld, SFD_CLOEXEC);
        if (sigchld_fd == -1) {
                TRACE_ERRNO("signalfd() failed");
                goto _out;
        }

	pid_t ssh_pid = fork_ssh(&sigchld, args);
	if (ssh_pid == -1)
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
		TRACE("signal received: signo=%i, code=%i, pid=%i, status=%i", si.ssi_signo, si.ssi_code, si.ssi_pid, si.ssi_status);
		if (si.ssi_signo != SIGCHLD || si.ssi_code != CLD_EXITED)
			continue;
		if (si.ssi_pid == ssh_pid) {
			int status;
			if (waitpid(ssh_pid, &status, 0) == 0) {
				TRACE_ERRNO("waitpid(%i) failed", ssh_pid);
				ssh_pid = -1;
				goto _out_kill;
			}
			ssh_pid = fork_ssh(&sigchld, args);
			if (ssh_pid == -1)
				goto _out_kill;
		}
		if (si.ssi_pid == client_pid) {
			if (WIFEXITED(si.ssi_status))
				rc = WEXITSTATUS(si.ssi_status);
			else
				rc = 1;
			break;
		}
	}

_out_kill:
	if (ssh_pid != -1) {
		if (kill(ssh_pid, SIGKILL) == -1)
			TRACE_ERRNO("kill(%i) failed", ssh_pid);
		int status;
		if (waitpid(ssh_pid, &status, 0) == -1)
			TRACE_ERRNO("waitpid(%i) failed", ssh_pid);
	}
	if (client_pid != -1) {
		if (kill(client_pid, SIGKILL) == -1)
			TRACE_ERRNO("kill(%i) failed", client_pid);
		int status;
		if (waitpid(client_pid, &status, 0) == -1)
			TRACE_ERRNO("waitpid(%i) failed", client_pid);
	}

_out_close_sigchld_fd:
	if (close(sigchld_fd) == -1)
		TRACE_ERRNO("close(%i) failed", sigchld_fd);

_out:
	return rc;
}
