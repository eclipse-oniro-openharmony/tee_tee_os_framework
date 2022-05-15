#include <sys/resource.h>
#include "syscall.h"
#include "libc.h"

int setrlimit(int resource, const struct rlimit *rlim)
{
	return 0;
}

weak_alias(setrlimit, setrlimit64);
