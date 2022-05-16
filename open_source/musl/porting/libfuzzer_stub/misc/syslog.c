#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>

int setlogmask(int maskpri)
{
	return 0;
}

void closelog(void)
{
}

void openlog(const char *ident, int opt, int facility)
{
}

static void __vsyslog(int priority, const char *message, va_list ap)
{
}

void syslog(int priority, const char *message, ...)
{
}

weak_alias(__vsyslog, vsyslog);
