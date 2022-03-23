#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <securec.h>
#include "libc.h"

/* Used when compiled with Linux with _FORTIFY_SOURCE. Latest GCC
 * version(>=4.1.0) has built-in printf check functions, so claim
 * weak_alias to support low version GCC.
 *
 * Sucessful check will return length of the format.
 *
 * */
int __vsprintf_chk(char *s, int flags, size_t slen, const char *format,
		   va_list args)
{
	int ret;
	ret = vsnprintf_s(s, slen, slen - 1, format, args);
	if (ret >= 0) {
		if ((size_t)ret > slen) {
			printf("buffer overflow detected\n");
			abort();
		}
	}
	return ret;
}
weak_alias(__vsprintf_chk, ___vsprintf_chk);
