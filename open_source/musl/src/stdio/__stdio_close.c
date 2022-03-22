#include "stdio_impl.h"

/* use console as stdio, just wrap console_close as __stdio_close */
int __stdio_close(FILE *f)
{
	return console_close(f);
}
