#include "stdio_impl.h"
#include "console.h"

/* Since console_seek is currently just a stub function, __stdio_seek is stub as well */
off_t __stdio_seek(FILE *f, off_t off, int whence)
{
	return console_seek(f, off, whence);
}
