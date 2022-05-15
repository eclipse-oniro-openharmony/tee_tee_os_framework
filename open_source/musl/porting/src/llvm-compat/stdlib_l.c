#include <stdlib.h>
#include <locale.h>

double strtod_l(const char *s, char **end_ptr,
		locale_t loc __attribute__((unused)))
{
	return strtod(s, end_ptr);
}

float strtof_l(const char *s, char **end_ptr,
	       locale_t loc __attribute__((unused)))
{
	return strtof(s, end_ptr);
}

long strtol_l(const char *s, char **end_ptr, int base,
	      locale_t loc __attribute__((unused)))
{
	return strtol(s, end_ptr, base);
}

long double strtold_l(const char *s, char **end_ptr,
		      locale_t loc __attribute__((unused)))
{
	return strtold(s, end_ptr);
}

long long strtoll_l(const char *s, char **end_ptr, int base,
		    locale_t loc __attribute__((unused)))
{
	return strtoll(s, end_ptr, base);
}

unsigned long strtoul_l(const char *s, char **end_ptr, int base,
			locale_t loc __attribute__((unused)))
{
	return strtoul(s, end_ptr, base);
}

unsigned long long strtoull_l(const char *s, char **end_ptr, int base,
			      locale_t loc __attribute__((unused)))
{
	return strtoull(s, end_ptr, base);
}
