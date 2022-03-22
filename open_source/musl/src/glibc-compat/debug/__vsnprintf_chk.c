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
int __vsnprintf_chk(char *s, size_t maxlen, int flags, size_t slen,
		    const char *format, va_list args)
{
	if (slen < maxlen) {
		printf("buffer overflow detected\n");
		abort();
	}
	return vsnprintf_s(s, slen, maxlen, format, args);
}
weak_alias(__vsnprintf_chk, ___vsnprintf_chk);
