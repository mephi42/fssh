#ifndef FSSH_ANYZMQ_H
#define FSSH_ANYZMQ_H

#include <zmq.h>

#if ZMQ_VERSION_MAJOR == 2
#	define zmq_ctx_new() zmq_init(1)
#	define zmq_ctx_term(context) zmq_term(context)
#	define zmq_msg_recv(msg, socket, flags) zmq_recv(socket, msg, flags)
#	define zmq_msg_send(msg, socket, flags) zmq_send(socket, msg, flags)
#	define ZMQ_DONTWAIT ZMQ_NOBLOCK
#elif ZMQ_VERSION < ZMQ_MAKE_VERSION(3, 3, 0)
#	define zmq_ctx_term(context) zmq_ctx_destroy(context)
#endif

#endif
