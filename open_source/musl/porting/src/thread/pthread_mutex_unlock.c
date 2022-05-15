#include "pthread_impl.h"

extern void mutex_node_free(struct mutex_link * p);

static volatile struct mutex_link *find_mutex_node(pthread_mutex_t *m, pthread_t self)
{
	volatile struct mutex_link *rp = NULL;

    if (m == NULL) {
        printf("invalid parameter\n");
        return NULL;
    }

#if defined (__arm__) && !defined (__aarch64__)
	rp = (struct mutex_link *)(uintptr_t)(self->robust_list.head & 0xffffffffU);
#elif !defined(__arm__) && defined (__aarch64__)
	rp = (struct mutex_link *)(uintptr_t)(self->robust_list.head);
#else
#error not arch supported
#endif
	while (rp != (void *)&self->robust_list.head) {
		if (rp->m == &m->_m_lock) {
			return rp;
		}
		rp = rp->next;
	}
	return NULL;
}

static void remove_robust_list(pthread_mutex_t *m, pthread_t self, volatile struct mutex_link *rp)
{
	if (rp != NULL) {
		volatile void *prev = rp->prev;
		volatile void *next = rp->next;
		*(volatile void *volatile *)prev = next;
		if (next != &self->robust_list.head) *(volatile void *volatile *)
			((char *)next + sizeof(void *)) = prev;
		mutex_node_free((void *)rp);
		rp = NULL;
		m->_m_link = -1;
	} else {
		printf("mutex link node not found!");
		abort();
	}
}

static inline void wake_waiters(pthread_mutex_t *m, int cont, int priv)
{
	int waiters = m->_m_waiters;
	if (waiters || cont<0)
		__wake(&m->_m_lock, 1, priv);
}

int __pthread_mutex_unlock(pthread_mutex_t *m)
{
	pthread_t self = NULL;
	int cont;
	unsigned int type = (unsigned int)m->_m_type & 15;
	int priv = ((unsigned int)m->_m_type & 128) ^ 128;

	if (type != PTHREAD_MUTEX_NORMAL) {
		self = __pthread_self();
		if (((unsigned int)m->_m_lock & 0x7fffffff) != self->tid)
			return EPERM;
		if ((type & 3) == PTHREAD_MUTEX_RECURSIVE && m->_m_count)
			return m->_m_count--, 0;
		if (!priv)
			__vm_lock();
	}
	cont = a_swap(&m->_m_lock, (type & 8) ? 0x7fffffff : 0);
	if (type != PTHREAD_MUTEX_NORMAL && !priv) {
		self->robust_list.pending = 0;
		__vm_unlock();
	}
	/*
	 * As remove_robust_list may call free and then call munmap which will call
	 * __vm_wait, this cause a deadlock on vmlock.
	 * So put remove_robust_list after __vm_unlock.
	 */
	if (type != PTHREAD_MUTEX_NORMAL) {
		volatile struct mutex_link *rp = find_mutex_node(m, self);
		remove_robust_list(m, self, rp);
	}
	wake_waiters(m, cont, priv);
	return 0;
}

weak_alias(__pthread_mutex_unlock, pthread_mutex_unlock);
