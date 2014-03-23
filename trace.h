#ifndef FSSH_TRACE_H
#define FSSH_TRACE_H

#include <errno.h>
#include <lttng/tracef.h>
#include <string.h>

#define TRACE(fmt, ...) tracef("%s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define TRACE_ERRNO(fmt, ...) \
	do { \
		int err = errno; \
		TRACE(fmt ": error %d (%s)", ##__VA_ARGS__, err, strerror(err)); \
	} while (0)

#endif
