#define _GNU_SOURCE
#include <unistd.h>
#include <time.h>

int usleep(unsigned useconds)
{
#ifndef CONFIG_LIBFUZZER
	struct timespec tv = {
		.tv_sec = useconds/1000000,
		.tv_nsec = (useconds%1000000)*1000
	};
	return nanosleep(&tv, &tv);
#else
	return 0;
#endif
}
