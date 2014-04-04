#ifndef FSSH_MESSAGE_H
#define FSSH_MESSAGE_H

enum msg_type {
	msg_type_stdin = 0,
	msg_type_stdout = 1,
	msg_type_stderr = 2,
	msg_type_exit = 3,
};

#endif
