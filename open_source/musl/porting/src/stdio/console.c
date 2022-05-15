#include <hm/io.h>
#include <stdio_impl.h>
#include <stdint.h>

#define MAXLEN(ptr) (UINTPTR_MAX - (uintptr_t)(ptr) + 1)

static int userland_console_getchar(void)
{
	int ch;
	ch = hm_debug_getchar_noblock();
	for (; ch < 0; ch = hm_debug_getchar_noblock())
		hm_yield();
	return ch;
}

/*
 * read from console
 * return when '\n' is typed, otherwise, stdin sometimes stub.
 * because stdin will read more bytes than request for buffering,
 * if no more input, it will wait.
 */
size_t console_read(FILE *file, void *data, size_t num_bytes)
{
	if (data == NULL || num_bytes == 0)
		return 0;
	char *ptr = (char *)data;
	num_bytes = (num_bytes <= MAXLEN(ptr)) ? num_bytes : MAXLEN(ptr);
	char *end = ptr + num_bytes - 1;
	while (ptr <= end) {
		*ptr = (char)userland_console_getchar();
		/* Translate DEL to BS */
		if (*ptr == 0x7f) *ptr = '\b';
		switch (*ptr) {
		case '\r':
		case '\n':
			hm_debug_putchar('\r');
			hm_debug_putchar('\n');
			*ptr++ = '\n';
			break;
		case '\b':
			if (ptr != (char *)data) {
				hm_debug_putchar('\b');
				// '\b' just put the cursor back one step, but the letter is still there
				// so need to put ' ' there to clean the letter
				hm_debug_putchar(' ');
				hm_debug_putchar('\b');
				ptr--;
			}
			break;
		default:
			if (*ptr >= ' ' && *ptr <= 0x7e) {
				hm_debug_putchar(*ptr);
				ptr++;
			}
			break;
		}
		// for '\n', input is end
		if (ptr != (char *)data && *(ptr - 1) == '\n') break;
	}
	return (size_t)(ptr - (char *)data);
}

size_t console_write(FILE *file, void *data, size_t num_bytes)
{
	if (data == NULL || num_bytes == 0)
		return 0;
	char *ptr = (char *)data;
	size_t sz = (num_bytes <= MAXLEN(ptr)) ? num_bytes : MAXLEN(ptr);
	size_t ret_num = sz;

	while (sz > 0) {
		size_t n = sz;
		if (n > HM_DEBUG_PUT_BYTES_LIMIT)
			n = HM_DEBUG_PUT_BYTES_LIMIT;
		// ignore errors, continue to print all data
		// even error occurs.
		(void)hm_debug_putbytes(ptr, n);
		ptr += n;
		sz -= n;
	}
	return ret_num;
}

size_t stdio_internal_refuse_write(FILE *file, const unsigned char *data,
				   size_t num_bytes)
{
	return 0;
}

int console_seek(FILE *file, off_t offset, int whence)
{
	return 0;
}

int console_close(FILE *file)
{
	return 0;
}

void ignore_free(FILE *file)
{
	/* Since the structures for stdin, stdout and stderr are
	   in static memory, do not free them. */
	return;
}
