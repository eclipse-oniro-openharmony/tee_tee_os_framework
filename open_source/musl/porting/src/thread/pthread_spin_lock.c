#include "pthread_impl.h"
#include <errno.h>

#include "sys/usrsyscall.h"

// As hongmeng OS don't have timer interrupt. we need hm_yield() in while loop.
// After hongmeng enable CPU timer, maybe we should remove hm_yield().
int pthread_spin_lock(pthread_spinlock_t *s)
{
	while (*(volatile int *)s || a_cas(s, 0, EBUSY)) {
		hm_yield();
		a_spin();
	}
	return 0;
}
