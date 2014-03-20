#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>

#include "ringbuf.h"

int ringbuf_init(struct ringbuf *rb, size_t size)
{
	rb->buf = mmap(NULL, size * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (rb->buf == MAP_FAILED) {
		perror("mmap() failed");
		goto _fail;
	}
	rb->size = size;
	rb->read = rb->buf;
	rb->write = rb->buf;

	int shm = shmget(IPC_PRIVATE, size, IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR);
	if (shm == -1) {
		perror("shmget() failed");
		goto _fail_shmget;
	}

	if (shmat(shm, rb->buf, SHM_REMAP) == (void*)-1) {
		perror("shmat() failed");
		goto _fail_shmat1;
	}

	if (shmat(shm, rb->buf + size, SHM_REMAP) == (void*)-1) {
		perror("shmat() failed");
		goto _fail_shmat2;
	}

	if (shmctl(shm, IPC_RMID, NULL) == -1)
		perror("shmctl() failed");

	return 0;

_fail_shmat2:
	if (shmdt(rb->buf) == -1)
		perror("shmdt() failed");
_fail_shmat1:
	if (shmctl(shm, IPC_RMID, NULL))
		perror("shmctl() failed");
_fail_shmget:
	if (munmap(rb->buf, size * 2))
		perror("munmap() failed");
_fail:
	return -1;
}

void ringbuf_reset(struct ringbuf *rb)
{
	if (shmdt(rb->buf) == -1)
		perror("shmdt() failed");
	if (shmdt(rb->buf + rb->size) == -1)
		perror("shmdt() failed");
	if (munmap(rb->buf, rb->size * 2) == -1)
		perror("munmap() failed");
}
