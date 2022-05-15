#define _GNU_SOURCE
#include <sched.h>
#include <string.h>
#include "pthread_impl.h"
#include "syscall.h"

int sched_setaffinity(pid_t tid, size_t size, const cpu_set_t *set)
{
    printf("sched_setaffinity is not supported now\n");
    return -ENOSYS;
}

int sched_getaffinity(pid_t tid, size_t size, cpu_set_t *set)
{
    printf("sched_getaffinity is not supported now\n");
    return -ENOSYS;
}
