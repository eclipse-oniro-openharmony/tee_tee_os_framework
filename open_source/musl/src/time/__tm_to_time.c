#include <time.h>
#include <errno.h>

#define D(a, b) ((a) > 0 ? (a) / (b) : -(((b) - (a) - 1) / (b)))

// Tralslate struct tm into time_t which is type defined by unsigned int
time_t __tm_to_time(const struct tm *tm)
{
	int    year;
	int    month;
	int    day;
	int z4, z100, z400;

	if (tm == NULL) {
		errno = EINVAL;
		return -1;
	}

	year  = tm->tm_year - 100;
	month = tm->tm_mon;
	day   = tm->tm_mday;

	/* normalize month */
	if (month >= 12) {
		year += month / 12;
		month %= 12;
	} else if (month < 0) {
		year += month / 12;
		month %= 12;
		if (month) {
			month += 12;
			year--;
		}
	}

	z4 = D(year - (month < 2), 4);
	z100 = D(z4, 25);
	z400 = D(z100, 4);

	day += year * 365 + z4 - z100 + z400 +
	month[(const int []) {
			       0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
		       }];

	return (time_t)((long long)day * 86400
			+ tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec
			- -946684800);
}
