#include <locale.h>
#include <langinfo.h>

static const char c_local_time[] =
	"Sun\0" "Mon\0" "Tue\0" "Wed\0" "Thu\0" "Fri\0"
	"Sat\0"	"Sunday\0" "Monday\0" "Tuesday\0"
	"Wednesday\0" "Thursday\0" "Friday\0"
	"Saturday\0" "Jan\0" "Feb\0" "Mar\0" "Apr\0" "May\0"
	"Jun\0" "Jul\0" "Aug\0" "Sep\0" "Oct\0" "Nov\0"
	"Dec\0" "January\0"   "February\0" "March\0"
	"April\0" "May\0"       "June\0"     "July\0"
	"August\0" "September\0" "October\0"  "November\0"
	"December\0" "AM\0" "PM\0" "%a %b %e %T %Y\0" "%m/%d/%y\0"
	"%H:%M:%S\0" "%I:%M:%S %p\0" "\0" "%m/%d/%y\0" "0123456789\0"
	"%a %b %e %T %Y\0" "%H:%M:%S";

static const char c_local_messages[] = "^[yY]\0" "^[nN]";
static const char c_local_numeric[] = ".\0" "";

//  _langinfo() returns a string which is the value corresponding to
//  item in the program's current global locale.
char *__langinfo(nl_item item)
{
	int mycat = (unsigned int)item >> 16;
	int myidx = (unsigned int)item & 65535;
	const char *str = NULL;

	if (item == CODESET) return "UTF-8";

	switch (mycat) {
	case LC_MESSAGES:
		if (myidx > 1) return NULL;
		str = c_local_messages;
		break;
	case LC_TIME:
		if (myidx > 0x31) return NULL;
		str = c_local_time;
		break;
	case LC_NUMERIC:
		if (myidx > 1) return NULL;
		str = c_local_numeric;
		break;
	case LC_MONETARY:
		if (myidx > 0) return NULL;
		str = "";
		break;
	default:
		return NULL;
	}

	for (; myidx; myidx--, str++) for (; *str; str++);
	return (char *)str;
}

weak_alias(__langinfo, nl_langinfo);
