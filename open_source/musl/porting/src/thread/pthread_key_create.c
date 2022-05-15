#include "pthread_impl.h"

static void (*volatile func[PTHREAD_KEYS_MAX])(void *);

static void nofunc(void *dummy)
{
}

int pthread_key_create(pthread_key_t *k, void (*dtor)(void *))
{
	uint32_t i = (((uintptr_t)&k) / 16) % PTHREAD_KEYS_MAX;
	uint32_t j = i;
	pthread_t self = __pthread_self();

	/* This can only happen in the main thread before
	 * pthread_create has been called. */
	if (self->tsd == NULL)
        self->tsd = __pthread_tsd_main;

	if (dtor == NULL)
        dtor = nofunc;
	do {
		if (!a_cas_p(func+j, 0, (void *)dtor)) {
			*k = j;
			return 0;
		}
	} while ((j=(j+1)%PTHREAD_KEYS_MAX) != i);
	return EAGAIN;
}

int pthread_key_delete(pthread_key_t k)
{
    if (k >= PTHREAD_KEYS_MAX)
        return EINVAL;

	func[k] = 0;
	return 0;
}

void __pthread_tsd_run_dtors()
{
	int i;
    int j;
	pthread_t self = __pthread_self();
    unsigned char used = self->tsd_used;
	for (j = 0; (used != 0) && (j < PTHREAD_DESTRUCTOR_ITERATIONS); j++) {
		used = 0;
		for (i = 0; i < PTHREAD_KEYS_MAX; i++) {
			if (self->tsd[i] && func[i]) {
				void *tmp = self->tsd[i];
				self->tsd[i] = 0;
				func[i](tmp);
				used = 1;
			}
		}
	}
}
