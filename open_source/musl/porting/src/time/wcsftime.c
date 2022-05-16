#include <time.h>
#include "time_impl.h"
// for string
#include <string.h>
// for wchar
#include <wchar.h>
// for mbstowcs
#include <stdlib.h>
#define BUF_SIZE 120
#define IN_SIZE  4


/*
 * The wcsftime() function converts the time and date specification in the timeptr
 * structure into a wide-character string. It then stores the null-ended string in
 * the array pointed to by wdest according to the format string pointed to
 * by format. The maxsize value specifies the maximum number of wide characters
 * that can be copied into the array.
 * This function is equivalent to strftime(), except that it uses wide characters.
 */
size_t wcsftime(wchar_t *restrict wcs, size_t n, const wchar_t *restrict f,
		const struct tm *restrict tm)
{
	size_t pos, n0 = n;
	char out[BUF_SIZE], input[IN_SIZE];
	if (!wcs || !f || !tm)
		return 0;
	while (*f) {
		if (!n) {
			return 0;
		}
		if (*f != '%') {
			n--;
			// wcs increase..
			*wcs++ = *f++;
			continue;
		}
		input[3] = 0;
		input[2] = 0;
		input[0] = (char) * f++;
		if (strchr("EO", (input[1] = (char) * f++))) {
			input[2] = (char)(*f++);
		}
		pos = strftime(out, sizeof out, input, tm);

		if (!pos) {
			return 0;
		}

		pos = mbstowcs(wcs, out, n);
		if (pos == (size_t) -1) {
			return 0;
		}
		wcs += pos;
		n -= pos;
	}
	if (!n) return 0;
	*wcs++ = 0;
	return n0 - n;
}
