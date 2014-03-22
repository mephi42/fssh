#ifndef FSSH_RINGBUF_H
#define FSSH_RINGBUF_H

#include <stddef.h>

struct ringbuf {
	void *buf;
	size_t size;
	void *read;
	void *write;
};

int ringbuf_init(struct ringbuf *rb, size_t size) __attribute__((warn_unused_result));

static inline size_t ringbuf_max_read(struct ringbuf *rb)
{
	if (rb->read <= rb->write)
		return rb->write - rb->read;
	else
		return rb->size - (rb->read - rb->write);
}

static inline void ringbuf_read(struct ringbuf *rb, size_t size)
{
	rb->read += size;
	if (rb->read >= rb->buf + rb->size)
		rb->read -= rb->size;
}

static inline size_t ringbuf_max_write(struct ringbuf *rb)
{
	if (rb->read <= rb->write)
		return rb->size - (rb->write - rb->read);
	else
		return rb->read - rb->write;
}

static inline void ringbuf_write(struct ringbuf *rb, size_t size)
{
	rb->write += size;
	if (rb->write >= rb->buf + rb->size)
		rb->write -= rb->size;
}

int ringbuf_reset(struct ringbuf *rb) __attribute__((warn_unused_result));

#endif
