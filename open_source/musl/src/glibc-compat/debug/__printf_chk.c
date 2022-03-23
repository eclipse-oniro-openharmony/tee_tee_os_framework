#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "libc.h"

/* Used when compiled with Linux with _FORTIFY_SOURCE. Latest GCC
 * version(>=4.1.0) has built-in printf check functions, so claim
 * weak_alias to support low version GCC.
 *
 * Sucessful check will return length of the format.
 *
 * */
int __printf_chk(int flag, const char *fmt, ...)
{
	va_list args;
	int ret;
	va_start(args, fmt);
	ret = vfprintf(stdout, fmt, args);
	va_end(args);
	return ret;
}
weak_alias(__printf_chk, ___printf_chk);
