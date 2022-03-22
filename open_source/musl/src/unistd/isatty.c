#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "syscall.h"

int isatty(int fd)
{
#ifndef CONFIG_LIBFUZZER
	struct winsize wsz;
	unsigned long r = syscall(SYS_ioctl, fd, TIOCGWINSZ, &wsz);
	if (r == 0) return 1;
	if (errno != EBADF) errno = ENOTTY;
#endif
	return 0;
}
