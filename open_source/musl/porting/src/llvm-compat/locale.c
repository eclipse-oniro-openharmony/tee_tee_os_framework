#include <errno.h>
#include <locale.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <wchar.h>
#include <threads.h>
#include <bits/alltypes.h>
#include <stdio.h>
#include <ctype.h>
#include <securec.h>
#include "locale_impl.h"
#include "libc.h"

#define LC_IDENTIFICATION 12

typedef struct __locale_struct *__locale_t;

// We only support two locales, the "C" locale (also known as "POSIX"),
// and the "C.UTF-8" locale (also known as "en_US.UTF-8").

static unsigned int  __bionic_current_locale_is_utf8 = 1;

size_t __ctype_get_mb_cur_max()
{
	return __bionic_current_locale_is_utf8 ? (size_t)4 : (size_t)1;
}

static unsigned int __is_supported_locale(const char *locale_name)
{
	return (unsigned int)(strcmp(locale_name, "") == 0 ||
			      strcmp(locale_name, "C") == 0 ||
			      strcmp(locale_name, "C.UTF-8") == 0 ||
			      strcmp(locale_name, "en_US.UTF-8") == 0 ||
			      strcmp(locale_name, "POSIX") == 0);
}

static unsigned int __is_utf8_locale(const char *locale_name)
{
	return (unsigned int)(*locale_name == '\0' || strstr(locale_name, "UTF-8"));
}

locale_t duplocale(locale_t l)
{
	locale_t new = NULL;
	new = calloc(1U, sizeof(*new));
	if (new == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	errno_t rc = memcpy_s(new, sizeof(*new), l, sizeof(*new));
	if (rc != EOK) {
		errno = rc;
		free(new);
		new = NULL;
	}
	return new;
}

#define __CTYPE_NTOHS(x) (((1 << (x)) >> 8) | (((1 << (x)) & 0xff) << 8))
enum {
	_ISupper = __CTYPE_NTOHS(0),
	_ISlower = __CTYPE_NTOHS(1),
	_ISalpha = __CTYPE_NTOHS(2),
	_ISdigit = __CTYPE_NTOHS(3),
	_ISxdigit = __CTYPE_NTOHS(4),
	_ISspace = __CTYPE_NTOHS(5),
	_ISprint = __CTYPE_NTOHS(6),
	_ISgraph = __CTYPE_NTOHS(7),
	_ISblank = __CTYPE_NTOHS(8),
	_IScntrl = __CTYPE_NTOHS(9),
	_ISpunct = __CTYPE_NTOHS(10),
	_ISalnum = __CTYPE_NTOHS(11),
};

#include "ctype_data.h"

#define __LC_LAST 13

struct __locale_struct c_locale = {
	{},
	c_locale_array  + 128, // __ctype_b
	c_tolower_array + 128, // __ctype_tolower
	c_toupper_array + 128, // __ctype_toupper
	{},                    // names
	{},                    // adapt ori musl libc
};

locale_t __c_locale_ptr = &c_locale;

#define _NL_CTYPE_CLASS  0
#define _NL_CTYPE_TOUPPER 1
#define _NL_CTYPE_TOLOWER 3
#define _NL_ITEM_INDEX(item) ((int) (item) & 0xffff)

struct __locale_data {
	const void *values[0];
};

int all_categories(int category_mask)
{
	return ((unsigned int)category_mask | (1 << LC_ALL)) == (1 << __LC_LAST) - 1;
}

__locale_t newlocale(int category_mask, const char *locale, locale_t base)
{
	if (category_mask == 1 << LC_ALL) {
		category_mask = ((1 << __LC_LAST) - 1) & ~(1 << LC_ALL);
	}
	if (locale == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if (base == &c_locale) {
		base = NULL;
	}
	if ((base == NULL || all_categories(category_mask))
	    && (category_mask == 0 || strcmp(locale, "C") == 0)) {
		return &c_locale;
	}
	struct __locale_struct result = base ? *base : c_locale;
	if (category_mask == 0) {
		__locale_t result_ptr = malloc(sizeof(struct __locale_struct));
		if (result_ptr == NULL) {
			errno = ENOMEM;
			return NULL;
		}

		*result_ptr = result;
		return result_ptr;
	}
	return NULL;
}

void freelocale(locale_t l)
{
	// In our implementation, newlocale() might return c_locale instead of
	// allocating a new copy of the locale... We can't free that.
	if (l == __c_locale_ptr) {
		return;
	}
	free(l);
}

char *setlocale(int category, const char *locale_name)
{
	// Is 'category' valid?
	if (category < LC_CTYPE || category > LC_IDENTIFICATION) {
		errno = EINVAL;
		return NULL;
	}

	// Caller wants to set the locale rather than just query?
	if (locale_name != NULL) {
		if (!__is_supported_locale(locale_name)) {
			// We don't support this locale.
			errno = ENOENT;
			return NULL;
		}
		__bionic_current_locale_is_utf8 = __is_utf8_locale(locale_name);
	}

	return (char *)(__bionic_current_locale_is_utf8 ? "C.UTF-8" : "C");
}

static locale_t *get_current_locale_ptr()
{
	return &(CURRENT_LOCALE);
}

locale_t uselocale(locale_t new_locale)
{
	locale_t old_locale = *get_current_locale_ptr();

	// If this is the first call to uselocale(3) on this thread, we return LC_GLOBAL_LOCALE.
	if (old_locale == NULL) {
		old_locale = LC_GLOBAL_LOCALE;
	}

	if (new_locale != NULL) {
		*get_current_locale_ptr() = new_locale;
	}

	return old_locale;
}
