#include "pthread_ext.h"
#include "pthread_impl.h"
#include "hm/thread.h"

pthread_t pthread_self()
{
	return (pthread_t)hmapi_tls_get()->thread_ptr;
}
