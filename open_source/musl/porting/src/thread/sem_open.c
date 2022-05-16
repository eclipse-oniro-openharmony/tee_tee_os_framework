#include <semaphore.h>
#include <sys/mman.h>
#include <limits.h>
#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include "lock.h"
#include <hm_mman.h>
#include <fcntl.h>
#include <string.h>
#include <securec.h>
#include <hmlog.h>
#include <hm/hm_stat.h>

// strchrnul is declared in string.h with _GNU_SOURCE
// but not declared in string.h without _GNU_SOURCE
// here need declaration. for libc internal, use __strchrnul instead
char *__strchrnul(const char *, int);

// HM shm(share memory) number is limit by 32(MAX_NUM_SHMEMFILE) in libmmgr/mman_svr.c
// semaphore number should less than shm number
#define HM_SEM_MAX 16
#define PREFIX_NAME_LEN 10
#define PREFIX_SEM_NAME "/sem/"
#define PREFIX_SEM_NAME_LEN strlen(PREFIX_SEM_NAME)

static struct {
	int fd;
	sem_t *sem;
	int refcnt;
} *semtab = NULL;
static volatile int lock[1];

/*
 * mapname is used in shm_open/shm_unlink in libc/musl
 * but hm_shm_open/hm_shm_unlink donot verify the name
 * so here verify the name in sem_open/sem_unlink
 * maybe move the name verifying to hm_shm later.
 */
char *__sem_mapname(const char *name, char *buf, size_t size)
{
	char *p = NULL;
	if (name == NULL || buf == NULL) {
		errno = EINVAL;
		return 0;
	}
	if (strnlen(name, NAME_MAX) == NAME_MAX) {
		errno = ENAMETOOLONG;
		return 0;
	}
	while (*name == '/')
		/* name will not be null because strnlen has execute before */
		name++;
	p = __strchrnul(name, '/');
	if (*p || p == name ||
	    (p - name <= 2 && name[0] == '.' && p[-1] == '.')) {
		errno = EINVAL;
		return 0;
	}

	errno_t rc;
	rc = memcpy_s(buf, size, PREFIX_SEM_NAME, PREFIX_SEM_NAME_LEN);
	if (rc) {
		errno = EINVAL;
		return 0;
	}

	if (size <= PREFIX_SEM_NAME_LEN) {
		errno = EINVAL;
		return 0;
	}
	rc = memcpy_s(buf + PREFIX_SEM_NAME_LEN, size - PREFIX_SEM_NAME_LEN, name,
		      (size_t)(p - name + 1));
	if (rc) {
		errno = EINVAL;
		return 0;
	}

	return buf;
}

sem_t *sem_open(const char *name, int flags, ...)
{
	va_list ap;
	int fd, rc, i, slot;
	unsigned int value;
	sem_t *sem = NULL;
	char buf[NAME_MAX + PREFIX_NAME_LEN];
	/* name will be check in __sem_mapname function */
	name = __sem_mapname(name, buf, sizeof(buf));
	if (name == NULL)
		return SEM_FAILED;

	LOCK(lock);
	if (!semtab) {
		semtab = calloc(sizeof(*semtab), HM_SEM_MAX);
		if (!semtab) {
			UNLOCK(lock);
			return SEM_FAILED;
		}
		for (i = 0; i < HM_SEM_MAX; i++)
			semtab[i].fd = -1;
	}

	for (i = 0; i < HM_SEM_MAX && semtab[i].sem; i++) {}
	if (i == HM_SEM_MAX) {
		errno = EMFILE;
		UNLOCK(lock);
		return SEM_FAILED;
	}
	slot = i;
	semtab[slot].sem = (sem_t *)-1;
	UNLOCK(lock);
	fd = hm_shm_open(name, flags, S_IRWXUGO);
	if (fd < 0) {
		errno = ENOMEM;
		goto fail;
	}
	if ((unsigned int)flags & O_CREAT) {
		rc = hm_shm_ftruncate(fd, sizeof(sem_t));
		if (rc < 0) {
			if (!hm_shm_close(fd))
				errno = ENOMEM;
			goto fail;
		}
	}
	sem = (sem_t *)mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			    0);
	if (sem == MAP_FAILED) {
		if (!hm_shm_close(fd))
			errno = ENOMEM;
		goto fail;
	}
	LOCK(lock);
	for (i = 0; i < HM_SEM_MAX && semtab[i].fd != fd; i++) {}
	if (i < HM_SEM_MAX) {
		// munmap the sem and reuse the existed sem
		if (munmap(sem, sizeof(sem_t)))
			hm_error("munmap failed\n");
		semtab[slot].sem = 0;
		slot = i;
		sem = semtab[i].sem;
	}
	/* for global variable will be initial by calloc function */
	semtab[slot].refcnt++;
	semtab[slot].sem = sem;
	semtab[slot].fd = fd;
	UNLOCK(lock);
	if ((unsigned int)flags & O_CREAT) {
		va_start(ap, flags);
		(void)va_arg(ap, mode_t);
		value = va_arg(ap, unsigned int);
		va_end(ap);
		// '1' means 'share'
		if (sem_init(sem, 1, value)) {
			rc = hm_shm_close(fd);
			if (rc)
				hm_error("hm_shm_close failed, return code %d\n", rc);
			goto fail2;
		}
	}
	return sem;
fail:
	LOCK(lock);
	semtab[slot].sem = 0;
	UNLOCK(lock);
	return SEM_FAILED;
fail2:
	LOCK(lock);
	semtab[slot].refcnt--;
	if (semtab[slot].refcnt == 0) {
		semtab[slot].sem = 0;
		semtab[slot].fd = -1;
		if (munmap(sem, sizeof(sem_t)))
			hm_error("munmap failed\n");
	}
	UNLOCK(lock);
	return SEM_FAILED;
}

int sem_close(sem_t *sem)
{
	int i, fd;
	int rc;
	if (sem == NULL)
		return -1;
	LOCK(lock);
	for (i = 0; i < HM_SEM_MAX && semtab[i].sem != sem; i++) {}
	if (i == HM_SEM_MAX) {
		errno = EINVAL;
		UNLOCK(lock);
		return -1;
	}

	fd = semtab[i].fd;
	if (!(--semtab[i].refcnt)) {
		semtab[i].sem = 0;
		semtab[i].fd = -1;
		if (munmap(sem, sizeof(sem_t)))
			hm_error("munmap failed\n");
	}
	UNLOCK(lock);

	rc = hm_shm_close(fd);
	if (rc != 0)
		hm_error("hm_shm_close failed, return code %d\n", rc);
	return rc;
}
