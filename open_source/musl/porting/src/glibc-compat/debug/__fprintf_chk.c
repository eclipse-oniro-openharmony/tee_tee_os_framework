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
int __fprintf_chk(FILE *fp, int flag, const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = vfprintf(fp, format, ap);
	va_end(ap);

	return ret;
}
weak_alias(__fprintf_chk, ___fprintf_chk);
