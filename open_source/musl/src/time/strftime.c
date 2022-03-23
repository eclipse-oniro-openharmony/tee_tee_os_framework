#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <securec.h>
#include <langinfo.h>

char *__langinfo(nl_item);
long  __local_timezone = 0;
int   __offset_of_dest = 0;
char *__tzname[2] = { 0, 0 };

static int strftime_check(const char *restrict s, const char *restrict f,
			  const struct tm *restrict tm)
{
	if (!s || !f || !tm)
		return 0;
	else return 1;
}

static int strftime_checkZ(const struct tm *restrict tm)
{
	if (tm->tm_isdst < 0 || !__tzname[0] || !__tzname[0][0])
		return 1;
	else
		return 0;
}

/*
 * The format specification is a null-terminated string and may contain
 * special character sequences called conversion specifications, each of
 * which is introduced by a '%' character and terminated by some other
 * character known as a conversion specifier character.  All other
 * character sequences are ordinary character sequences.
 */
size_t strftime(char *restrict s, size_t n, const char *restrict f,
		const struct tm *restrict tm)
{
	nl_item myitem;
	int myval;
	const char *myfmt = NULL;
	size_t l;
	const char *strTemp = NULL;

	if (!strftime_check(s, f, tm))
       return 0;

	for (l = 0; *f && l < n; f++) {
		if (*f == '%') {
__do_my_fmt:
			switch (*++f) {
			case '%':
				goto __literal;
			case 'E':
			case 'O':
				goto __do_my_fmt;
			case 'A':
				myitem = DAY_1 + tm->tm_wday;
				goto __nl_strcat;
			case 'a':
				myitem = ABDAY_1 + tm->tm_wday;
				goto __nl_strcat;
			case 'h':
			case 'b':
				myitem = ABMON_1 + tm->tm_mon;
				goto __nl_strcat;
			case 'B':
				myitem = MON_1 + tm->tm_mon;
				goto __nl_strcat;
			case 'c':
				myitem = D_T_FMT;
				goto __nl_strftime;
			case 'C':
				myval = (1900 + tm->tm_year) / 100;
				myfmt = "%02d";
				goto __number;
			case 'd':
				myval = tm->tm_mday;
				myfmt = "%02d";
				goto __number;
			case 'D':
				myfmt = "%m/%d/%y";
				goto __recu_strftime;
			case 'e':
				myval = tm->tm_mday;
				myfmt = "%2d";
				goto __number;
			case 'F':
				myfmt = "%Y-%m-%d";
				goto __recu_strftime;
			case 'G':
				myval = 0; // week_based_year(tm);
				myfmt = "%04d";
				goto __number;
			case 'g':
				myval = 0; // week_based_year(tm)%100;
				myfmt = "%02d";
				goto __number;
			case 'H':
				myval = tm->tm_hour;
				myfmt = "%02d";
				goto __number;
			case 'I':
				myval = tm->tm_hour;
				if (!myval) myval = 12;
				else if (myval > 12) myval -= 12;
				myfmt = "%02d";
				goto __number;
			case 'j':
				myval = tm->tm_yday + 1;
				myfmt = "%03d";
				goto __number;
			case 'm':
				myval = tm->tm_mon + 1;
				myfmt = "%02d";
				goto __number;
			case 'M':
				myval = tm->tm_min;
				myfmt = "%02d";
				goto __number;
			case 'n':
				s[l++] = '\n';
				continue;
			case 'p':
				myitem = tm->tm_hour >= 12 ? PM_STR : AM_STR;
				goto __nl_strcat;
			case 'r':
				myitem = T_FMT_AMPM;
				goto __nl_strftime;
			case 'R':
				myfmt = "%H:%M";
				goto __recu_strftime;
			case 'S':
				myval = tm->tm_sec;
				myfmt = "%02d";
				goto __number;
			case 't':
				s[l++] = '\t';
				continue;
			case 'T':
				myfmt = "%H:%M:%S";
				goto __recu_strftime;
			case 'u':
				myval = tm->tm_wday ? tm->tm_wday : 7;
				myfmt = "%d";
				goto __number;
			case 'U':
			case 'V':
			case 'W':
				continue;
			case 'w':
				myval = tm->tm_wday;
				myfmt = "%d";
				goto __number;
			case 'x':
				myitem = D_FMT;
				goto __nl_strftime;
			case 'X':
				myitem = T_FMT;
				goto __nl_strftime;
			case 'y':
				myval = tm->tm_year % 100;
				myfmt = "%02d";
				goto __number;
			case 'Y':
				myval = tm->tm_year + 1900;
				myfmt = "%04d";
				goto __number;
			case 'z':
				if (tm->tm_isdst < 0) continue;
				myval = (int)(-__local_timezone - (tm->tm_isdst ? __offset_of_dest : 0));
				l += snprintf_s(s + l, n - l, n - l - 1,  "%+.2d%.2d", myval / 3600,
						abs(myval % 3600) / 60);
				continue;
			case 'Z':
				if (strftime_checkZ(tm))
					continue;
				l += snprintf_s(s + l, n - l, n - l - 1, "%s", __tzname[!!tm->tm_isdst]);
				continue;
			default:
				return 0;
			}
           }
__literal:
		s[l++] = *f;
		continue;
__number:
		l += snprintf_s(s + l, n - l, n - l - 1, myfmt, myval);
		continue;
__nl_strcat:
		l += snprintf_s(s + l, n - l, n - l - 1, "%s", __langinfo(myitem));
		continue;
__nl_strftime:
		strTemp = (const char *)__langinfo(myitem);
		if (strTemp != NULL) {
			myfmt = strTemp;
		} else {
			continue;
		}
__recu_strftime:
		l += strftime(s + l, n - l, myfmt, tm);
	}
	if (l >= n) return 0;
	s[l] = 0;
	return l;
}

size_t strftime_l(char *restrict s, size_t n, const char *restrict f,
		  const struct tm *restrict tm, locale_t loc __attribute__((unused)))
{
	return strftime(s, n, f, tm);
}
