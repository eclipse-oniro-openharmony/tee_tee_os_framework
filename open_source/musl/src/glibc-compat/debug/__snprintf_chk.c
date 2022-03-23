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
int __snprintf_chk(char *s, size_t n, int flag, size_t slen,
		   const char *format, ...)
{
	va_list args;
	int ret;
	va_start(args, format);
	ret = __vsnprintf_chk(s, n, flag, slen, format, args);
	if (ret >= 0) {
		if ((size_t)ret > slen) {
			printf("buffer overflow detected\n");
			abort();
		}
	}
	va_end(args);
	return ret;
}
weak_alias(__snprintf_chk, ___snprintf_chk);
