#include <stddef.h>		/* NULL */
#include <stdio.h>
#include <stdio_impl.h>
#include <hm/io.h>
#include <malloc.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "console.h"

#ifndef O_TRUNC
# define O_TRUNC 0
#endif

#ifndef O_CREAT
# define O_CREAT 0
#endif

#ifndef O_APPEND
# define O_APPEND 0
#endif

static size_t
fdio_read(FILE *file, unsigned char *data, size_t num_bytes)
{
	if (file == NULL || data == NULL)
		return 0;
	ssize_t result = read(file->fd, data, num_bytes);

	if (result < 0) {
		file->flags |= F_ERR;
		return 0;
	} else if (result == 0 && num_bytes > 0) {
		// num_bytes > 0 and result == 0, so EOF
		file->flags |= F_EOF;
	}

	return (size_t)result;
}

static size_t
fdio_write(FILE *file, const unsigned char *data, size_t num_bytes)
{
	if (file == NULL || data == NULL)
		return 0;
	ssize_t result = write(file->fd, data, num_bytes);

	if (result < 0) {
		file->flags |= F_ERR;
		return 0;
	}

	return (size_t)result;
}

static off_t
fdio_seek(FILE *file, off_t offset, int whence)
{
	if (file == NULL) {
		errno = EINVAL;
		return -1;
	}
	return lseek(file->fd, offset, whence);
}

static int
fdio_close(FILE *file)
{
	if (file == NULL) {
		errno = EINVAL;
		return -1;
	}
	return close(file->fd);
}

struct mode_to_flags_s {
	const char *string;
	int flags;
};

static const struct mode_to_flags_s translate[] = {
	{ "r", O_RDONLY },
	{ "r+", O_RDWR },
	{ "w", O_WRONLY | O_TRUNC },
	{ "w+", O_RDWR | O_CREAT },
	{ "a", O_WRONLY | O_APPEND },
	{ "a+", O_RDWR | O_APPEND },
};

static int
mode_to_flag(const char *mode_orig, int *flags_out)
{
	unsigned long i;	/* long because it is compared with sizeof */
	char filter_b[3];	/* max str mode len */
	const char *mode = mode_orig;

	if (mode_orig == NULL || flags_out == NULL)
		return -1;
	/* Remove the letter "b" from the mode: */
	i = 0;
	while (*mode != '\0') {
		if (i >= sizeof(filter_b) - 1) {
			return -1;
		}
		if (*mode != 'b')
			filter_b[i++] = *mode;
		mode++;
	}
	filter_b[i] = '\0';

	for (i = 0; i < sizeof(translate) / sizeof(translate[0]); i++) {
		if (!strncmp(filter_b, translate[i].string, sizeof(filter_b) - 1)) {
			*flags_out = translate[i].flags;
			return 0;
		}
	}

	return -1;
}

static inline void
init_ops_and_fd(FILE *file, int fd, int flags)
{
	file->read = fdio_read;
	file->write = (flags == O_RDONLY) ? stdio_internal_refuse_write : fdio_write;
	file->seek = fdio_seek;
	file->close = fdio_close;
	file->fd = fd;
}

static FILE*
fdopen_with_flags(int fd, int flags)
{
	FILE *file = calloc(1U, sizeof(FILE));
	if (file == NULL) {
		return NULL;
	}

	init_ops_and_fd(file, fd, flags);
	return file;
}

FILE*
fdopen(int fd, const char *mode)
{
	int flags;

	if (mode_to_flag(mode, &flags) < 0) {
		errno = EINVAL;
		return NULL;
	}

	FILE *fp = fdopen_with_flags(fd, flags);
	if (fp == NULL) {
		errno = ENFILE;
		return NULL;
	}

	return fp;
}

FILE*
fopen(const char *filepath, const char *mode)
{
	int flags;

	if (filepath == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if (mode_to_flag(mode, &flags) < 0) {
		errno = EINVAL;
		return NULL;
	}
	int fd = open(filepath, flags, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		errno = ENFILE;
		return NULL;
	}

	FILE *fp = fdopen_with_flags(fd, flags);
	if (fp == NULL) {
		if (!close(fd))
			errno = ENFILE;
		return NULL;
	}

	return fp;
}

FILE*
freopen(const char *filepath, const char *mode, FILE *file)
{
	int flags;
	int err;

	if (!filepath || !file) {
		errno = EINVAL;
		return NULL;
	}

	if (mode_to_flag(mode, &flags) < 0) {
		errno = EINVAL;
		return NULL;
	}

	err = file->close(file);
	if (err) {
		errno = ENFILE;
		return NULL;
	}

	int fd = open(filepath, flags);
	if (fd < 0) {
		errno = ENFILE;
		return NULL;
	}

	file->flags &= ~F_EOF;
	file->flags &= ~F_ERR;
	init_ops_and_fd(file, fd, flags);

	return file;
}
