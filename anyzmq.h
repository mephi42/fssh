#ifndef FSSH_ANYZMQ_H
#define FSSH_ANYZMQ_H

#include <zmq.h>

#if ZMQ_VERSION_MAJOR == 2

#define zmq_ctx_new() zmq_init(1)
#define zmq_ctx_term zmq_term
#define zmq_msg_recv zmq_recv
#define zmq_msg_send zmq_send
#define ZMQ_DONTWAIT ZMQ_NOBLOCK

#endif

#endif
