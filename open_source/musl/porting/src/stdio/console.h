#ifndef _STDIO_CONSOLE_H
#define _STDIO_CONSOLE_H

#include <stdio.h>

// hongmeng console functions
size_t console_read(FILE *, void *, size_t);
size_t console_write(FILE *, void *, size_t);
int console_seek(FILE *, off_t, int);
int console_close(FILE *);

size_t stdio_internal_refuse_write(FILE *file, const unsigned char *data,
				   size_t num_bytes_orig);

#endif
