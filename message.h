#ifndef FSSH_MESSAGE_H
#define FSSH_MESSAGE_H

#include <zmq.h>

enum msg_type {
	msg_type_stdin = 0,
	msg_type_stdout = 1,
	msg_type_stderr = 2,
	msg_type_exit = 3,
};

int get_msg_type(zmq_msg_t *msg);

int on_fd_readable(int *fd, void *socket, zmq_msg_t *msg, int *msg_valid, char msg_type);
int fd_write(int *fd, zmq_msg_t *msg, size_t *msg_pos);
int socket_write(void *socket, zmq_msg_t *msg, int *msg_valid);

#endif
