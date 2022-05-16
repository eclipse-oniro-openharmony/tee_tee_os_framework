#include <stdio.h>
#include <stdlib.h>

// A nonstandard assert which might be changed later in pratice
void __assert2(const char *file, int line, const char *func,
	       const char *failedexpr)
{
	printf("assertion \"%s\" failed: file \"%s\", line %d, function \"%s\"\n",
	       failedexpr, file, line, func);
	abort();
}
