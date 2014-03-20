#ifndef FSSH_RINGBUF_H
#define FSSH_RINGBUF_H

struct ringbuf {
	void *buf;
	size_t size;
	void *read;
	void *write;
};

int ringbuf_init(struct ringbuf *rb, size_t size);

__attribute__((unused)) static size_t ringbuf_max_read(struct ringbuf *rb)
{
	if (rb->read <= rb->write)
		return rb->write - rb->read;
	else
		return rb->size - (rb->read - rb->write);
}

__attribute__((unused)) static void ringbuf_read(struct ringbuf *rb, size_t size)
{
	rb->read += size;
	if (rb->read >= rb->buf + rb->size)
		rb->read -= rb->size;
}

 __attribute__((unused)) static size_t ringbuf_max_write(struct ringbuf *rb)
{
	if (rb->read <= rb->write)
		return rb->size - (rb->write - rb->read);
	else
		return rb->read - rb->write;
}

__attribute__((unused)) static void ringbuf_write(struct ringbuf *rb, size_t size)
{
	rb->write += size;
	if (rb->write >= rb->buf + rb->size)
		rb->write -= rb->size;
}

void ringbuf_reset(struct ringbuf *rb);

#endif
