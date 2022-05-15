#include "stdio_impl.h"
#include "pthread_impl.h"

// maybe need replace __lockfile/__unlockfile with true implementation
int __lockfile(FILE *f)
{
    return 1;
}

void __unlockfile(FILE *f)
{
	return;
}
