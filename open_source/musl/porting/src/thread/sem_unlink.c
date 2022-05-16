#include <hm_mman.h>
#include <semaphore.h>
#include <limits.h>

char *__sem_mapname(const char *name, char *buf, size_t size);

/* We need to confirm that there is no semantic difference between  hm_shm_unlink and linux shm_unlink */
#define PREFIX_NAME_LEN 10

int sem_unlink(const char *name)
{
	char buf[NAME_MAX + PREFIX_NAME_LEN];
	name = __sem_mapname(name, buf, sizeof(buf));
	if (name == NULL)
		return -1;
	return hm_shm_unlink(name);
}
