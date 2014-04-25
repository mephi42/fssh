#include "sbuf.h"
#include <stdlib.h>
#include <string.h>
#include "trace.h"

int sbuf_init(struct sbuf *sbuf, size_t size)
{
	sbuf->s = malloc(size);
	if (sbuf->s == NULL) {
		TRACE("malloc(%zu) failed", size);
		return -1;
	}
	sbuf->size = size;
	sbuf->pos = 0;
	sbuf->s[sbuf->pos] = 0;
	return 0;
}

void sbuf_reset(struct sbuf *sbuf)
{
	free(sbuf->s);
}

int sbuf_ensure_capacity(struct sbuf *sbuf, size_t capacity)
{
	while (capacity >= sbuf->size) {
		char *orig = sbuf->s;
		sbuf->s = realloc(sbuf->s, sbuf->size * 2);
		if (sbuf->s == orig) {
			TRACE("realloc(%zu) failed", sbuf->size * 2);
			return -1;
		}
		sbuf->size *= 2;
	}
	return 0;
}

int sbuf_append(struct sbuf *sbuf, const char *s, size_t n)
{
	if (sbuf_ensure_capacity(sbuf, sbuf->pos + n) == -1)
		return -1;
	memcpy(sbuf->s + sbuf->pos, s, n);
	sbuf->pos += n;
	sbuf->s[sbuf->pos] = 0;
	return 0;
}

int sbuf_append_string(struct sbuf *sbuf, const char *s)
{
	return sbuf_append(sbuf, s, strlen(s));
}

