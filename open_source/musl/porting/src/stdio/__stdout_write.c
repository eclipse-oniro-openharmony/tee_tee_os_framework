#include "stdio_impl.h"
#include <sys/ioctl.h>

/* Wrapper function that writes to stdio_write */
size_t __stdout_write(FILE *f, const unsigned char *buf, size_t len)
{
	if (f != NULL)
		f->write = __stdio_write;
	return __stdio_write(f, buf, len);
}
