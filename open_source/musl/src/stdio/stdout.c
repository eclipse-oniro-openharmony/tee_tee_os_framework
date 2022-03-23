#include "stdio_impl.h"
#include <securec.h>

#undef stdout

static unsigned char buf[BUFSIZ+UNGET];
hidden FILE __stdout_FILE = {
	.buf = buf + UNGET,
	.buf_size = sizeof(buf) - UNGET,
	.fd = 1,
	.flags = F_PERM | F_NORD,
	.lbf = '\n',
	.write = __stdout_write,
	.seek = __stdio_seek,
	.close = __stdio_close,
	.lock = -1,
};
FILE* const stdout = &__stdout_FILE;
FILE *volatile __stdout_used = &__stdout_FILE;

void __reset_stdout(void)
{
	/* we don't care the return value, and cannot call print here */
	(void)memset_s(&__stdout_FILE, sizeof(__stdout_FILE), 0, sizeof(__stdout_FILE));

	__stdout_FILE.buf = buf + UNGET;
	__stdout_FILE.buf_size = sizeof(buf) - UNGET;
	__stdout_FILE.fd = 1;
	__stdout_FILE.flags = F_PERM | F_NORD;
	__stdout_FILE.lbf = '\n';
	__stdout_FILE.write = __stdout_write;
	__stdout_FILE.seek = __stdio_seek;
	__stdout_FILE.close = __stdio_close;
	__stdout_FILE.lock = -1;
}
