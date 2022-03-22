#include <sched.h>
#include <sys/usrsyscall.h>

int sched_yield(void)
{
	hm_yield();
	return 0;
}
