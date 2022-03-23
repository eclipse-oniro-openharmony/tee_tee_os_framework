#include <stdarg.h>
#include <wchar.h>

int swprintf(wchar_t *restrict s, size_t n, const wchar_t *restrict fmt, ...)
{
#ifndef CONFIG_LIBFUZZER
	int ret;
	va_list ap;
	va_start(ap, fmt);
	ret = vswprintf(s, n, fmt, ap);
	va_end(ap);
	return ret;
#else
	return 0;
#endif
}

