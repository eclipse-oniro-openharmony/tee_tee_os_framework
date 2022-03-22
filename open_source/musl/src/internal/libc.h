#ifndef _LOCAL_LIBC_H
#define _LOCAL_LIBC_H

#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include "sys/cdefs.h"  /* for __BEGIN_DECLS */

__BEGIN_DECLS

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

extern void _chk_fail(const char *func);

extern void __funcs_on_exit(void);


struct __libc {
	void *main_thread;
	int threaded;
	int secure;
	FILE *ofl_head;
	volatile int threads_minus_1;
};

// compatible with glibc implement
struct __locale_struct {
	struct __locale_data *__locales[13];
	const unsigned short int *__ctype_b;
	const int *__ctype_tolower;
	const int *__ctype_toupper;
	const char *__names[13];
};

typedef struct __locale_struct *__locale_t;
typedef __locale_t locale_t;

extern hidden struct __libc __libc;
#define libc __libc

hidden void __init_libc(char **, char *);
hidden void __init_tls(size_t *);
hidden void __init_ssp(void *);
hidden void __libc_start_init(void);
hidden void __funcs_on_quick_exit(void);
hidden void __libc_exit_fini(void);
hidden void __fork_handler(int);

extern hidden const char __libc_version[];

#endif
__END_DECLS
