#include <unistd.h>
#include <procmgr.h>

/* Get pid of the current thread */
pid_t getpid()
{
	return hm_getpid();
}
