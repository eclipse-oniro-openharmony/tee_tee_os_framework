#include "stdio_impl.h"
#include <stdint.h>
#include "console.h"

// NEED_struct_iovec should before alltypes.h
#define __NEED_struct_iovec
#define __NEED_off_t
#include <bits/alltypes.h>

#define MAXLEN(ptr) (UINTPTR_MAX - (uintptr_t)(ptr) + 1)

size_t __stdio_read(FILE *f, unsigned char *buf, size_t len)
{
	if (f == NULL || buf == NULL || len == 0)
		return 0;
	len = (len <= MAXLEN(buf)) ? len : MAXLEN(buf);
	// for friendly using, flush stdout before reading from stdin
	(void)fflush(stdout);
	struct iovec iov[2] = {
		{ .iov_base = buf, .iov_len = len - !!f->buf_size },
		{ .iov_base = f->buf, .iov_len = f->buf_size }
	};
	size_t cnt;
	cnt = console_read(f, iov[0].iov_base, iov[0].iov_len);
	if (cnt < iov[0].iov_len) return cnt;
	cnt = console_read(f, iov[1].iov_base, iov[1].iov_len);
	if (cnt == 0) return iov[0].iov_len;
	f->rpos = f->buf;
	f->rend = f->buf + cnt;
	if (f->buf_size) buf[len-1] = *f->rpos++;
	return len;
}
