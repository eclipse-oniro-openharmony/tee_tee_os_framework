#include "pthread_impl.h"

int pthread_mutexattr_setrobust(pthread_mutexattr_t *a, int robust)
{
	if (robust > 1)
        return EINVAL;

    a->__attr =  ((a->__attr) & (~4)) | (robust * 4);
	return 0;
}
