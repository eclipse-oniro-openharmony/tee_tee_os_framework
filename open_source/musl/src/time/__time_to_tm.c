#include <errno.h>
#include <time.h>

#define D(a, b) ((a) > 0 ? (a) / (b) : -(((b) - (a) - 1) / (b)))

#define DAYS_PER_400Y (365*400 + 97)
#define DAYS_PER_100Y (365*100 + 24)
#define DAYS_PER_4Y   (365*4   + 1)

struct tm *__time_to_tm(time_t t, struct tm *tm)
{
	/* months are march-based */
	static const int days_from_month[] = { 31, 61, 92, 122, 153, 184, 214, 245, 275, 306, 337, 366 };
	long long bigday;
	int day, year4, year100;
	int year, year400;
	int month;
	int leap;
	int wday, mday, yday;
	int hour, min, sec;

	if (tm == NULL) {
		errno = EINVAL;
		return NULL;
	}

	/* start from 2000-03-01 (multiple of 400 years) */
	/* since 946684800 smaller MAX_LONG_NUMBER
	 * long is enough
	 */
	t += (time_t)(-946684800L - 86400 * (31 + 29));

	bigday = (long long)D(t, 86400);
	sec = (int)(t - bigday * 86400);

	hour = sec / 3600;
	sec -= hour * 3600;
	min = sec / 60;
	sec -= min * 60;

	/* 2000-03-01 was a wednesday */
	wday = (int)((3 + bigday) % 7);
	if (wday < 0)
		wday += 7;

	year400 = (int)D(bigday,
			 DAYS_PER_400Y); /* bacause DAYS_PER_400Y is a large number to ensure year400 not lead */
	day = (int)(bigday - year400 * DAYS_PER_400Y);

	year100 = day / DAYS_PER_100Y;
	if (year100 == 4)
		year100--;
	day -= year100 * DAYS_PER_100Y;

	year4 = day / DAYS_PER_4Y;
	if (year4 == 25)
		year4--;
	day -= (int)(year4 * DAYS_PER_4Y);

	year = (int)(day / 365);
	if (year == 4)
		year--;
	day -= (int)(year * 365);

	leap = !year && (year4 || !year100);
	yday = (int)(day + 31 + 28 + leap);
	if (yday >= 365 + leap)
		yday -= 365 + leap;

	year += (int)(4 * year4 + 100 * year100 + 400 * year400 + 2000 - 1900);

	for (month = 0; month < 12 && days_from_month[month] <= day; month++);
	if (month)
		day -= days_from_month[month - 1];
	month += 2;
	if (month >= 12) {
		month -= 12;
		year++;
	}

	mday = (int)(day + 1);

	tm->tm_sec = sec;
	tm->tm_min = min;
	tm->tm_hour = hour;
	tm->tm_mday = mday;
	tm->tm_mon = month;
	tm->tm_year = year;
	tm->tm_wday = wday;
	tm->tm_yday = yday;
	tm->__tm_zone = "UTC";
	tm->__tm_gmtoff = 0;

	return tm;
}
