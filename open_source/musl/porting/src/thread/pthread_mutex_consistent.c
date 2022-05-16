#include "pthread_impl.h"

int pthread_mutex_consistent(pthread_mutex_t *m)
{
	if (m->_m_type & 8 == 0)
        return EINVAL;

	if (__pthread_self()->tid != (m->_m_lock & 0x7fffffff))
		return EPERM;

	m->_m_type = (m->_m_type) & (~8U);

	return 0;
}
