#include "stdio_impl.h"
#include <securec.h>

#undef stdin

static unsigned char buf[BUFSIZ + UNGET];
hidden FILE __stdin_FILE = {
	.buf = buf + UNGET,
	.buf_size = sizeof(buf) - UNGET,
	.fd = 0,
	.flags = F_PERM | F_NOWR,
	.read = __stdio_read,
	.seek = __stdio_seek,
	.close = __stdio_close,
	.lock = -1,
};
FILE * const stdin = &__stdin_FILE;
FILE * volatile __stdin_used = &__stdin_FILE;

void __reset_stdin(void)
{
	/* don't care the return value, and cannot call print here */
	(void)memset_s(&__stdin_FILE, sizeof(__stdin_FILE), 0, sizeof(__stdin_FILE));

	__stdin_FILE.buf = buf + UNGET;
	__stdin_FILE.buf_size = sizeof(buf) - UNGET;
	__stdin_FILE.flags = F_PERM | F_NOWR;
	__stdin_FILE.read = __stdio_read;
	__stdin_FILE.seek = __stdio_seek;
	__stdin_FILE.close = __stdio_close;
	__stdin_FILE.lock = -1;
}
