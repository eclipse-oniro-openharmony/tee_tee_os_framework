#define _GNU_SOURCE
#include <sched.h>
#include <string.h>
#include <errno.h>
#include "pthread_impl.h"
#include "syscall.h"

#define HIGH_TRANS_BITS 32

int sched_setaffinity(pid_t tid, size_t size, const cpu_set_t *set)
{
    printf("this api is not supported now\n");
    return -ENOSYS;
}

int pthread_setaffinity_np(pthread_t td, size_t size, const cpu_set_t *set)
{
    if (set == NULL)
        return -EINVAL;

#ifdef CONFIG_TA_AFFINITY
    struct pthread *thread = (struct pthread *)(uintptr_t)td;
#ifdef __aarch64
    return -__syscall(SYS_sched_setaffinity, (long)thread->cref, size, set);
#else
    return -__syscall(SYS_sched_setaffinity, (long)thread->cref,
       (long)(thread->cref >> HIGH_TRANS_BITS), size, set);
#endif

#else
    return -__syscall(SYS_sched_setaffinity, td->tid, size, set);
#endif
}

static int do_getaffinity(pid_t tid, size_t size, cpu_set_t *set)
{
	long ret = __syscall(SYS_sched_getaffinity, tid, size, set);
	if (ret < 0) return ret;
	if (ret < size) memset((char *)set+ret, 0, size-ret);
	return 0;
}

int sched_getaffinity(pid_t tid, size_t size, cpu_set_t *set)
{
    printf("this api is not supported now\n");
    return -ENOSYS;
}

int pthread_getaffinity_np(pthread_t td, size_t size, cpu_set_t *set)
{
    if (set == NULL)
        return -EINVAL;

#ifdef CONFIG_TA_AFFINITY
    struct pthread *thread = (struct pthread *)(uintptr_t)td;
#ifdef __aarch64
    return -__syscall(SYS_sched_getaffinity, thread->cref, size, set);
#else
    return -__syscall(SYS_sched_getaffinity, (long)thread->cref,
        (long)(thread->cref >> HIGH_TRANS_BITS), size, set);
#endif
#else
    return -do_getaffinity(td->tid, size, set);
#endif
}
