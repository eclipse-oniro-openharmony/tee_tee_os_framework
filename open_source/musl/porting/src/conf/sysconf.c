#include <stdio.h>

// stubbed sysconf function which we do not support at the moment
long sysconf(int name __attribute__((unused)))
{
	printf("sysconf() is not supported now.\n");
	return -1L;
}
