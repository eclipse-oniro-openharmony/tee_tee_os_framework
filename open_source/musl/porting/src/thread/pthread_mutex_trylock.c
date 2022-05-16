#include <api/errno.h>
#include "pthread_impl.h"
#include "stdio.h"

static volatile struct mutex_link * mutex_node_alloc()
{
	return (struct mutex_link *)malloc(sizeof(struct mutex_link));
}

void mutex_node_free(struct mutex_link * p)
{
    if (p == NULL) {
        printf("invalid mutex node\n");
        return;
    }
	p->next = NULL;
	p->prev = NULL;
	p->m = NULL;
	free(p);
}

static int insert_robust_list(pthread_mutex_t *m, pthread_t self)
{
#if defined (__arm__) && !defined (__aarch64__)
	void *rhead = &self->robust_list.head;
	volatile void *next = (void *)(uintptr_t)(self->robust_list.head & 0xffffffffU);
	volatile struct mutex_link *m_link = mutex_node_alloc();
	if (m_link == NULL) {
		return ENOMEM;
	}
	m_link->m = &m->_m_lock;
	m_link->next = next;
	m_link->prev = rhead;

	/* To avoid warnings of m_link resource leak,
	 * leverage the fact that m_link == &m_link->next
	 */
	if (next != rhead) {
		*(volatile void *volatile *)((char *)next + sizeof(void *)) = m_link;
	}
	self->robust_list.head = ((uint64_t)(uintptr_t)m_link) & 0xffffffffULL;

#elif !defined(__arm__) && defined (__aarch64__)
	volatile void *next = (void *)(uintptr_t)self->robust_list.head;
	volatile struct mutex_link *m_link = mutex_node_alloc();
	if (m_link == NULL) {
		return ENOMEM;
	}
	m_link->m = &m->_m_lock;
	m_link->next = next;
	m_link->prev = &self->robust_list.head;

	/* To avoid warnings of m_link resource leak,
	 * leverage the fact that m_link == &m_link->next
	 */
	if (next != &self->robust_list.head) {
		*(volatile void *volatile *)((char *)next + sizeof(void *)) = m_link;
	}
	self->robust_list.head = (uint64_t)(uintptr_t)m_link;
#else
#error not arch supported
#endif
	return 0;
}

/*
 * Should only been used by  __pthread_mutex_trylock and
 * _m_type should is likely not PTHREAD_MUTEX_NORMAL
 */
int __pthread_mutex_trylock_owner(pthread_mutex_t *m)
{
	unsigned int old, own;
	unsigned int type = (unsigned int)m->_m_type & 15;
	pthread_t self = __pthread_self();
	int tid = (int)self->tid;

	old = m->_m_lock;
	own = old & 0x7fffffff;

	if ((int)own == tid && (type & 3) == PTHREAD_MUTEX_RECURSIVE) {
		if ((unsigned)m->_m_count >= INT_MAX) return EAGAIN;
		m->_m_count++;
		return 0;
	}

	/* he mutex you are trying to acquire is protecting state left irrecoverable by the mutex's previous owner that died
	 * while holding the lock. The mutex has not been acquired. This condition can occur when the lock was previously
	 * acquired with EOWNERDEAD and the owner was unable to cleanup the state and had unlocked the mutex without making
	 * the mutex state consistent.
	 */
	if (own == 0x7fffffff) return ENOTRECOVERABLE;

	if ((unsigned int)m->_m_type & 128) {
		if (!self->robust_list.off) {
			self->robust_list.off = (char *)&((struct mutex_link *)0)->m - (char *)&((struct mutex_link *)0)->next;
			long rc;
			rc = __syscall(SYS_set_robust_list, (intptr_t)&self->robust_list, sizeof(self->robust_list));
			if (rc != E_EX_OK) {
				if (rc == -ENOSYS)
					return ENOSYS;
				/* an other return code is E_EX_INVAL */
				else
					return EINVAL;
			}
		}
		if (m->_m_waiters) tid = (int)((unsigned int)tid | 0x80000000U);
//		self->robust_list.pending = __convert2uint64(&m->_m_next);
	}

	if ((own && (!(own & 0x40000000) || !(type & 4)))
	    || a_cas(&m->_m_lock, old, tid) != (int)old) {
		self->robust_list.pending = 0;
		return EBUSY;
	}
	if (insert_robust_list(m, self)) {
		return ENOMEM;
	}
	self->robust_list.pending = 0;

	if (own) {
		m->_m_count = 0;
		m->_m_type = (unsigned int)m->_m_type | 8;
		return EOWNERDEAD;
	}

	return 0;
}

int __pthread_mutex_trylock(pthread_mutex_t *m)
{
	if (((unsigned int)m->_m_type & 15) == PTHREAD_MUTEX_NORMAL)
		return (unsigned int)a_cas(&m->_m_lock, 0, EBUSY) & EBUSY;
	return __pthread_mutex_trylock_owner(m);
}

weak_alias(__pthread_mutex_trylock, pthread_mutex_trylock);
