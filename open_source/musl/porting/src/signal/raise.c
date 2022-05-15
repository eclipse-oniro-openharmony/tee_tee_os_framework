#include <stdio.h>

// stubbed raise api which we have not implemented
int raise(int sig __attribute__((unused)))
{
	printf("Warning: raise is not supported yet\n");
	return -1;
}
