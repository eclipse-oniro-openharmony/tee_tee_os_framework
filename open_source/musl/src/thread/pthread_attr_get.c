#include "pthread_impl.h"

int pthread_attr_getdetachstate(const pthread_attr_t *a, int *state)
{
	*state = ((unsigned int)a->_a_flag & PTHREAD_CREATE_DETACHED) ? PTHREAD_CREATE_DETACHED :
		 PTHREAD_CREATE_JOINABLE;
	return 0;
}

int pthread_attr_getguardsize(const pthread_attr_t *restrict a, size_t *restrict size)
{
	*size = a->_a_guardsize;
	return 0;
}

int pthread_attr_getinheritsched(const pthread_attr_t *restrict a, int *restrict flag)
{
	if (((unsigned int)a->_a_flag & PTHREAD_ATTR_FLAG_INHERIT) != 0) {
		*flag = PTHREAD_INHERIT_SCHED;
	} else if (((unsigned int)a->_a_flag & PTHREAD_ATTR_FLAG_EXPLICIT) != 0) {
		*flag = PTHREAD_EXPLICIT_SCHED;
	} else {
		*flag = (a->_a_policy != SCHED_NORMAL) ? PTHREAD_EXPLICIT_SCHED :
			PTHREAD_INHERIT_SCHED;
	}
	return 0;
}

int pthread_attr_getschedparam(const pthread_attr_t *restrict a, struct sched_param *restrict param)
{
	param->sched_priority = a->_a_prio;
	return 0;
}

int pthread_attr_getschedpolicy(const pthread_attr_t *restrict a, int *restrict policy)
{
	*policy = a->_a_policy;
	return 0;
}

int pthread_attr_getscope(const pthread_attr_t *restrict a, int *restrict scope)
{
	*scope = PTHREAD_SCOPE_SYSTEM;
	return 0;
}

/*
 * ARG: a, addr, size: controller by user input, need check NULL
 * ARITHOVF: this is get function. actually no need check. But
 *           pthread_attr_setstack(musl) has no check. So need
 *           to check addr overflow.
 */
int pthread_attr_getstack(const pthread_attr_t *restrict a, void **restrict addr, size_t *restrict size)
{
	if (!a->_a_stackaddr)
		return EINVAL;
	if (a->_a_stackaddr - a->_a_stacksize > a->_a_stackaddr)
		return EINVAL;
	*size = a->_a_stacksize;
	*addr = (void *)(uintptr_t)(a->_a_stackaddr - *size);
	return 0;
}

int pthread_attr_getstacksize(const pthread_attr_t *restrict a, size_t *restrict size)
{
	*size = a->_a_stacksize;
	return 0;
}

int pthread_mutexattr_getprotocol(const pthread_mutexattr_t *restrict a, int *restrict protocol)
{
	*protocol = PTHREAD_PRIO_NONE;
	return 0;
}

int pthread_mutexattr_getpshared(const pthread_mutexattr_t *restrict a, int *restrict pshared)
{
	*pshared = (int)(a->__attr / 128U % 2);
	return 0;
}

int pthread_mutexattr_getrobust(const pthread_mutexattr_t *restrict a, int *restrict robust)
{
	*robust = (int)(a->__attr / 4U % 2);
	return 0;
}

int pthread_mutexattr_gettype(const pthread_mutexattr_t *restrict a, int *restrict type)
{
	*type = (int)(a->__attr & 3);
	return 0;
}
