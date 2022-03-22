#include "stdio_impl.h"
#include <stdint.h>

#define MAXLEN(ptr) (UINTPTR_MAX - (uintptr_t)(ptr) + 1)

size_t __stdio_write(FILE *f, const unsigned char *buf, size_t len)
{
	if (f == NULL)
		return 0;
	len = (len <=  MAXLEN(buf)) ? len : MAXLEN(buf);
	struct iovec iovs[2] = {
		{ .iov_base = (void *)f->wbase, .iov_len = (size_t)(f->wpos - f->wbase) },
		{ .iov_base = (void *)buf, .iov_len = len }
	};
	struct iovec *iov = iovs;
	size_t cnt = 0;
	while (iov <= &iovs[1]) {
		cnt += console_write(f, (char *)iov->iov_base + cnt, iov->iov_len - cnt);
		if (cnt == iov->iov_len) {
			iov++;
			cnt = 0;
		}
	}
	f->wend = f->buf + f->buf_size;
	f->wpos = f->wbase = f->buf;
	return len;
}
