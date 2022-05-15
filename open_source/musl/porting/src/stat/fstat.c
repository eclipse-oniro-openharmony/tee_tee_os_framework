#include <sys/stat.h>
#include <stdio.h>

// stubbed fstat api which we have not implemented
int fstat(int fd __attribute__((unused)),
	  struct stat *st __attribute__((unused)))
{
	printf("fstat stubbed\n");
	return -1;
}
