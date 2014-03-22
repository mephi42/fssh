#define _GNU_SOURCE

#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>

#include "ringbuf.h"
#include "trace.h"

int ringbuf_init(struct ringbuf *rb, size_t size)
{
	rb->buf = mmap(NULL, size * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (rb->buf == MAP_FAILED) {
		TRACE_ERRNO("mmap(%d) failed", size * 2);
		goto _fail;
	}
	rb->size = size;
	rb->read = rb->buf;
	rb->write = rb->buf;

	int shm = shmget(IPC_PRIVATE, size, IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR);
	if (shm == -1) {
		TRACE_ERRNO("shmget(%d) failed", size);
		goto _fail_shmget;
	}

	if (shmat(shm, rb->buf, SHM_REMAP) == (void*)-1) {
		TRACE_ERRNO("shmat(%d, %p) failed", shm, rb->buf);
		goto _fail_shmat1;
	}

	if (shmat(shm, rb->buf + size, SHM_REMAP) == (void*)-1) {
		TRACE_ERRNO("shmat(%d, %p) failed", shm, rb->buf + size);
		goto _fail_shmat2;
	}

	if (shmctl(shm, IPC_RMID, NULL) == -1)
		TRACE_ERRNO("shmctl(%d) failed", shm);

	return 0;

_fail_shmat2:
	if (shmdt(rb->buf) == -1)
		TRACE_ERRNO("shmdt(%p) failed", rb->buf);
_fail_shmat1:
	if (shmctl(shm, IPC_RMID, NULL))
		TRACE_ERRNO("shmctl(%d) failed", shm);
_fail_shmget:
	if (munmap(rb->buf, size * 2))
		TRACE_ERRNO("munmap(%p, %d) failed", rb->buf, size * 2);
_fail:
	return -1;
}

int ringbuf_reset(struct ringbuf *rb)
{
	int rc = 0;

	if (shmdt(rb->buf) == -1) {
		TRACE_ERRNO("shmdt(%p) failed", rb->buf);
		rc = -1;
	}

	if (shmdt(rb->buf + rb->size) == -1) {
		TRACE_ERRNO("shmdt(%p) failed", rb->buf + rb->size);
		rc = -1;
	}

	if (munmap(rb->buf, rb->size * 2) == -1) {
		TRACE_ERRNO("munmap(%p, %d) failed", rb->buf, rb->size * 2);
		rc = -1;
	}

	return rc;
}
