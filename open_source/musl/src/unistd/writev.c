#include <sys/uio.h>
#include <stdio.h>

ssize_t writev(int fd, const struct iovec *iov, int count)
{
	printf("writev stubbed\n");
	return -1;
}
