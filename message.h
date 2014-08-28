#ifndef FSSH_MESSAGE_H
#define FSSH_MESSAGE_H

#include "anyzmq.h"

enum msg_type {
	msg_type_stdin  = 0,
	msg_type_stdout = 1,
	msg_type_stderr = 2,
	msg_type_exit   = 3,
};

int get_msg_hdr(zmq_msg_t *msg);

// Message header is 1 byte long and has the following format:
//
//   S S S S S S T T
//   7.6.5.4.3.2.1.0
//
// where S is sequence number and T is type.

#define MSG_HDR_TYPE_BITS 2
#define MSG_HDR_SEQ_BITS  6
#define MSG_HDR_TYPE_MASK ((1 << MSG_HDR_TYPE_BITS) - 1)
#define MSG_HDR_SEQ_MASK  ((1 << MSG_HDR_SEQ_BITS) - 1)

#define MSG_HDR(type, seq) ((((seq) & MSG_HDR_SEQ_MASK) << MSG_HDR_TYPE_BITS) | ((type) & MSG_HDR_TYPE_MASK))
#define MSG_HDR_TYPE(hdr)  ((hdr) & MSG_HDR_TYPE_MASK)
#define MSG_HDR_SEQ(hdr)   (((hdr) >> MSG_HDR_TYPE_BITS) & MSG_HDR_SEQ_MASK)

int on_fd_readable(int *fd, void *socket, zmq_msg_t *msg, int *msg_valid, char msg_type, int *msg_seq);
int fd_write(int *fd, zmq_msg_t *msg, size_t *msg_pos);
int socket_write(void *socket, zmq_msg_t *msg, int *msg_valid);

#endif
