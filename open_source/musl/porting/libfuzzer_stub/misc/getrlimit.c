#include <sys/resource.h>
#include "syscall.h"
#include "pthread_impl.h"

int getrlimit(int resource, struct rlimit *rlim)
{
    switch (resource) {
    case RLIMIT_STACK:
        rlim->rlim_cur = DEFAULT_STACK_SIZE;
        rlim->rlim_max = DEFAULT_STACK_SIZE;
        break;
    default:
        return -1;
    }
    return 0;
}

weak_alias(getrlimit, getrlimit64);
