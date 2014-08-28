#define _GNU_SOURCE

#include <fcntl.h>
#include "reset.h"
#include "sbuf.h"
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include "trace.h"
#include "un.h"
#include <unistd.h>

#define GUID_BINARY_SIZE 16
#define GUID_STRING_SIZE (GUID_BINARY_SIZE * 2 + 1)

static int guid_init(char guid[GUID_STRING_SIZE])
{
	int rc = -1;
	int fd = open("/dev/urandom", O_RDONLY);
	if  (fd == -1) {
		TRACE_ERRNO("open(/dev/urandom) failed");
		goto _out;
	}
	char bytes[GUID_BINARY_SIZE];
	if (read(fd, bytes, GUID_BINARY_SIZE) == -1) {
		TRACE_ERRNO("read() failed");
		goto _out_close;
	}
	for (int i = 0, j = 0; i < GUID_BINARY_SIZE; ++i)
		j += snprintf(guid + j, GUID_STRING_SIZE - j, "%.02x", (int)bytes[i] & 0xff);
	TRACE("guid=%s", guid);
	rc = 0;
_out_close:
	if (close(fd) == -1)
		TRACE_ERRNO("close(%i) failed");
_out:
	return rc;
}

struct names {
	char client_socket[128];
	char client_zmq_endpoint[128];
	char server_socat_address[128];
	char server_zmq_endpoint[128];
};

static int names_init(struct names *names)
{
	int rc = -1;
	char guid[33];
	if (guid_init(guid) == -1)
		goto _out;
	snprintf(names->client_socket, sizeof(names->client_socket), "/tmp/fssh-client-%s", guid);
	snprintf(names->client_zmq_endpoint, sizeof(names->client_zmq_endpoint), "ipc:///tmp/fssh-client-%s", guid);
	snprintf(names->server_socat_address, sizeof(names->server_socat_address), "UNIX-CONNECT:/tmp/fssh-server-%s,retry=3", guid);
	snprintf(names->server_zmq_endpoint, sizeof(names->server_zmq_endpoint), "ipc:///tmp/fssh-server-%s", guid);
	rc = 0;
_out:
	return rc;
}

static int get_nonopt_index(int argn, int argc, char **argv)
{
	for (int i = argn; i < argc; ++i) {
		if (argv[i][0] != '-')
			return i;
		switch (argv[i][1]) {
		case 'b': case 'c': case 'D': case 'E':
		case 'e': case 'F': case 'I': case 'i':
		case 'L': case 'l': case 'm': case 'O':
		case 'o': case 'p': case 'Q': case 'R':
		case 'S': case 'W': case 'w':
			++i;
			break;
		}
	}
	return -1;
}

static int get_pgm_index(int argc, char **argv)
{
	int hostname_index = get_nonopt_index(0, argc, argv);
	if (hostname_index == -1)
		return -1;
	return get_nonopt_index(hostname_index + 1, argc, argv);
}

static int ssh_command_append(struct sbuf *s, const char *arg)
{
	const char *current = arg, *next;
	while ((next = strchr(current, '\'')) != NULL) {
		if (sbuf_append(s, current, next - current) == -1)
			return -1;
		if (sbuf_append_string(s, "\\'") == -1)
			return -1;
		current = next + 1;
	}
	if (sbuf_append_string(s, current) == -1)
		return -1;
	return 0;
}

static int ssh_command_init(struct sbuf *s, const struct names *names, int argc, char **argv)
{
	if (sbuf_init(s, 64) == -1)
		goto _fail;
	if (sbuf_append_string(s, "fssh-fwd ") == -1)
		goto _fail_reset;
	if (sbuf_append_string(s, names->server_socat_address) == -1)
		goto _fail_reset;
	if (sbuf_append_string(s, " ") == -1)
		goto _fail_reset;
	if (sbuf_append_string(s, names->server_zmq_endpoint) == -1)
		goto _fail_reset;
	if (sbuf_append_string(s, " /bin/sh -c '") == -1)
		return -1;
	for (int i = 0; i < argc; ++i) {
		if (i != 0 && sbuf_append_string(s, " ") == -1)
			goto _fail_reset;
		if (ssh_command_append(s, argv[i]) == -1)
			goto _fail_reset;
	}
	if (sbuf_append_string(s, "'") == -1)
		return -1;
	return 0;

_fail_reset:
	sbuf_reset(s);
_fail:
	return -1;
}

__attribute__((noreturn)) static void exec_ssh(const char *unix_socket, const char *const *argv)
{
	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, unix_socket, sizeof(sa.sun_path));

	if (unlink(sa.sun_path) == -1) {
		if (errno != ENOENT) {
			TRACE("unlink(%s) failed", sa.sun_path);
			goto _fail;
		}
	}

	int server = un_listen(&sa);
	if (server == -1) {
		TRACE("un_listen(%s) failed", sa.sun_path);
		goto _fail;
	}

	int client = accept(server, NULL, NULL);
	if (client == -1) {
		TRACE_ERRNO("accept(%i) failed", server);
		goto _fail;
	}

	if (close(server) == -1)
		TRACE_ERRNO("close(%i) failed", server);
	server = -1;

	if (dup2(client, STDIN_FILENO) == -1) {
		TRACE_ERRNO("dup2(%i, %i) failed", client, STDIN_FILENO);
		goto _fail;
	}

	if (dup2(client, STDOUT_FILENO) == -1) {
		TRACE_ERRNO("dup2(%i, %i) failed", client, STDOUT_FILENO);
		goto _fail;
	}

	if (close(client) == -1)
		TRACE_ERRNO("close(%i) failed", client);
	client = -1;

	if (execvp(argv[0], (char**)argv) == -1) {
		TRACE_ERRNO("exec(%s) failed", argv[0]);
		goto _fail;
	}

_fail:
	_exit(1);
}

static pid_t fork_ssh(sigset_t *sigchld, const char *unix_socket, const char *const *argv)
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
		exec_ssh(unix_socket, argv);
	}
	TRACE("forked ssh, pid=%i", pid);
	return pid;
}

__attribute__((noreturn)) static void exec_client(struct names *names)
{
	char *args[3];
	args[0] = "fssh-client";
	args[1] = names->client_zmq_endpoint;
	args[2] = NULL;
	if (execvp(args[0], args) == -1)
		TRACE_ERRNO("exec(%s) failed", args[0]);
	_exit(1);
}

static pid_t fork_client(sigset_t *sigchld, struct names *names)
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
		exec_client(names);
	}
	TRACE("forked fssh-client, pid=%i", pid);
	return pid;
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
	for (int i = 0; i < argc; ++i)
	{
		TRACE("argv[%i] = %s", i, argv[i]);
	}

	int pgmn = get_pgm_index(argc - 1, argv + 1);
	if (pgmn == -1) {
		fprintf(stderr, "Usage: %s [SSH_OPTIONS] [USER@]HOSTNAME PGM [ARGS]...\n", argv[0]);
		return 1;
	}
	const char *ssh_argv[1 + pgmn + 2];

	int rc = 1;

	struct names names;
	if (names_init(&names) == -1)
		goto _out;

	struct sbuf ssh_command;
	if (ssh_command_init(&ssh_command, &names, argc - 1 - pgmn, argv + 1 + pgmn) == -1) {
		TRACE("ssh_command_init() failed");
		goto _out;
	}
	TRACE("ssh_command=%s", ssh_command.s);

	int sshn = 0;
	ssh_argv[sshn++] = "ssh";
	for (int argn = 1; argn <= pgmn; )
		ssh_argv[sshn++] = argv[argn++];
	ssh_argv[sshn++] = ssh_command.s;
	ssh_argv[sshn++] = NULL;

	sigset_t sigchld;
	if (sigemptyset(&sigchld) == -1) {
	        TRACE_ERRNO("sigemptyset() failed");
	        goto _out_free_ssh_command;
	}
	if (sigaddset(&sigchld, SIGCHLD) == -1) {
	        TRACE_ERRNO("sigaddset() failed");
	        goto _out_free_ssh_command;
	}
	if (sigprocmask(SIG_BLOCK, &sigchld, NULL) == -1) {
	        TRACE_ERRNO("sigprocmask() failed");
	        goto _out_free_ssh_command;
	}
	int sigchld_fd = signalfd(-1, &sigchld, SFD_CLOEXEC);
	if (sigchld_fd == -1) {
	        TRACE_ERRNO("signalfd() failed");
	        goto _out_free_ssh_command;
	}

	pid_t ssh_pid = fork_ssh(&sigchld, names.client_socket, ssh_argv);
	if (ssh_pid == -1)
		goto _out_close_sigchld_fd;

	pid_t client_pid = fork_client(&sigchld, &names);
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
				client_pid = -1;
				goto _out_kill;
			}
			if (pid == ssh_pid) {
				ssh_pid = fork_ssh(&sigchld, names.client_socket, ssh_argv);
				if (ssh_pid == -1)
					goto _out_kill;
			}
		}
	}

_out_kill:
	if (ssh_pid != -1)
		terminate_process(ssh_pid);
	if (client_pid != -1)
		terminate_process(client_pid);

_out_close_sigchld_fd:
	if (close(sigchld_fd) == -1)
		TRACE_ERRNO("close(%i) failed", sigchld_fd);

_out_free_ssh_command:
	sbuf_reset(&ssh_command);

_out:
	return rc;
}
