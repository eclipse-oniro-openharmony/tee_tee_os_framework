#ifndef _LOCALE_IMPL_H
#define _LOCALE_IMPL_H

#include <locale.h>
#include <stdlib.h>
#include "libc.h"
#include "pthread_impl.h"

#define LOCALE_NAME_MAX 23

extern hidden const struct __locale_struct __c_locale;
extern hidden const struct __locale_struct __c_dot_utf8_locale;

hidden const struct __locale_map *__get_locale(int, const char *);
hidden const char *__mo_lookup(const void *, size_t, const char *);
hidden const char *__lctrans(const char *, const struct __locale_map *);
hidden const char *__lctrans_cur(const char *);
hidden const char *__lctrans_impl(const char *, const struct __locale_map *);
hidden int __loc_is_allocated(locale_t);
hidden char *__gettextdomain(void);

#define LOC_MAP_FAILED ((const struct __locale_map *)-1)

#define LCTRANS(msg, lc, loc) __lctrans(msg, (loc)->cat[(lc)])
#define LCTRANS_CUR(msg) __lctrans_cur(msg)

#define C_LOCALE ((locale_t)&__c_locale)
#define UTF8_LOCALE ((locale_t)&__c_dot_utf8_locale)

#define CURRENT_LOCALE (__pthread_self()->locale)


#undef MB_CUR_MAX
#define __INTRODUCED_IN(api_level) __attribute__((annotate("introduced_in=" #api_level)))

#if __ANDROID_API__ >= __ANDROID_API_L__
size_t __ctype_get_mb_cur_max(void);
#define MB_CUR_MAX __ctype_get_mb_cur_max()
#else
/*
 * Pre-L we didn't have any locale support and so we were always the POSIX
 * locale. POSIX specifies that MB_CUR_MAX for the POSIX locale is 1:
 * http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/stdlib.h.html
 */
#define MB_CUR_MAX 1
#endif

#endif
