#include <sys/auxv.h>
#include <errno.h>
#include "libc.h"

unsigned long __getauxval(unsigned long item)
{
	errno = ENOENT;
	return 0;
}

weak_alias(__getauxval, getauxval);
