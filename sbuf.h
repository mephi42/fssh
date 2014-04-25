#ifndef FSSH_SBUF_H
#define FSSH_SBUF_H

#include <stddef.h>

struct sbuf {
	char *s;
	size_t size;
	size_t pos;
};

int sbuf_init(struct sbuf *sbuf, size_t size);
void sbuf_reset(struct sbuf *sbuf);
int sbuf_ensure_capacity(struct sbuf *sbuf, size_t capacity);
int sbuf_append(struct sbuf *sbuf, const char *s, size_t n);
int sbuf_append_string(struct sbuf *sbuf, const char *s);

#endif
