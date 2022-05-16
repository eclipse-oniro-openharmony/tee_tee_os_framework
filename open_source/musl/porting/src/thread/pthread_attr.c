#include <errno.h>

#include "hm/thread.h"
#include "pthread_impl.h"

int __pthread_attr_copy(pthread_attr_t *a, const pthread_attr_t *b)
{
	if (a == NULL || b == NULL) return EINVAL;
	a->_a_flag = b->_a_flag;
	a->_a_prio = b->_a_prio;
	a->_a_policy = b->_a_policy;
	a->_a_stackaddr = b->_a_stackaddr;
	a->_a_stacksize = b->_a_stacksize;
	a->_a_guardsize = b->_a_guardsize;
	a->_a_ca = b->_a_ca;
	a->_a_task_id = b->_a_task_id;
	return 0;
}

/* initialize pthread attributes.
 * NOTE: _a_ca & _a_task_id is tee specific thus this is no longer posix ?
 */
int pthread_attr_init(pthread_attr_t *a)
{
	// Can't use memset_s here!!!
	// As musl pthread_attr_t has 36 bytes, but 24 bytes in bionic, if we use memset_s to reset the attribute to zero,
	// we may access more memory!!!!
	if (a == NULL) return EINVAL;
	a->_a_flag = 0;
	a->_a_prio = 0;
	a->_a_policy = 0;
	a->_a_stackaddr = 0;
	a->_a_stacksize = DEFAULT_STACK_SIZE;
	a->_a_guardsize = DEFAULT_GUARD_SIZE;
	a->_a_ca = TEESMP_THREAD_ATTR_INVALID;
	a->_a_task_id = TEESMP_THREAD_ATTR_INVALID;
	return 0;
}

int pthread_attr_setdetachstate(pthread_attr_t *a, int state)
{
	if (a == NULL) return EINVAL;
	if (state == PTHREAD_CREATE_DETACHED) {
		a->_a_flag = (unsigned int)a->_a_flag | PTHREAD_ATTR_FLAG_DETACHED;
	} else if (state == PTHREAD_CREATE_JOINABLE) {
		a->_a_flag = (unsigned int)a->_a_flag & ~PTHREAD_ATTR_FLAG_DETACHED;
	} else {
		return EINVAL;
	}
	return 0;
}

/*
  sets the inherit-scheduler attribute of the thread attributes object referred to by
  attr to the value specified in inheritsched. The inherit-scheduler
  attribute determines whether a thread created using the thread
  attributes object attr will inherit its scheduling attributes from
  the calling thread or whether it will take them from attr.

  NOTE: There should be only two possibilities of flags that can be passed in

  1. PTHREAD_INHERIT_SCHED
  2. PTHREAD_EXPLICIT_SCHED

  However we translated the above possibilities into PTHREAD_ATTR_FLAGS_INHERIT(EXPLICIT).
*/
int pthread_attr_setinheritsched(pthread_attr_t *a, int flag)
{
	if (a == NULL) return EINVAL;
	if (flag == PTHREAD_EXPLICIT_SCHED) {
		a->_a_flag = (unsigned int)a->_a_flag & ~PTHREAD_ATTR_FLAG_INHERIT;
		a->_a_flag = (unsigned int)a->_a_flag | PTHREAD_ATTR_FLAG_EXPLICIT;
	} else if (flag == PTHREAD_INHERIT_SCHED) {
		a->_a_flag = (unsigned int)a->_a_flag | PTHREAD_ATTR_FLAG_INHERIT;
		a->_a_flag = (unsigned int)a->_a_flag & ~PTHREAD_ATTR_FLAG_EXPLICIT;
	} else {
		return EINVAL;
	}
	return 0;
}

/* NOTE: not generic posix thread stuff
 *  Bind ca with task_id and set/clr shadow flag
 */
int pthread_attr_settee(pthread_attr_t *a, int ca, int task_id, int shadow)
{
	if (a == NULL) return EINVAL;
	a->_a_ca = ca;
	a->_a_task_id = task_id;
	if (shadow == TEESMP_THREAD_ATTR_HAS_SHADOW)
		a->_a_flag = (unsigned int)a->_a_flag | PTHREAD_ATTR_FLAG_SHADOW;
	else
		a->_a_flag = (unsigned int)a->_a_flag & ~PTHREAD_ATTR_FLAG_SHADOW;
	return 0;
}
