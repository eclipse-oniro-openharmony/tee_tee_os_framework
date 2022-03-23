#include <stdio.h>
#include <stdlib.h>


_Noreturn void __assert_fail(const char *expr, const char *file, int line, const char *func)
{
	fprintf(stderr, "Assertion failed: %s (%s: %s: %d)\n", expr, file, func, line);
	fflush(NULL);
	abort();
}

// A nonstandard assert which might be changed later in pratice
void __assert2(const char *file, int line, const char *func,
	       const char *failedexpr)
{
	printf("assertion \"%s\" failed: file \"%s\", line %d, function \"%s\"\n",
	       failedexpr, file, line, func);
	abort();
}
