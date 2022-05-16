#ifndef _PTHREAD_EXT_H
#define _PTHREAD_EXT_H

#include "../../include/pthread.h"
#include "posix_types.h"

// NOTE: __pthread_self is used by musl libc itself.
//       pthread_arch.h implement __pthread_self function as static inline function.
//       But we have different behavior on Hongmeng OS.
//       SO we won't include this header file, but implement __pthread_self ourself.
pthread_t pthread_self();

static inline pthread_t __pthread_self()
{
	return pthread_self();
}

struct mutex_link {
	volatile void *next;
	volatile void *prev;
	volatile void *m;
};

#define PTHREAD_ATTR_FLAG_DETACHED 0x00000001
#define PTHREAD_ATTR_FLAG_INHERIT 0x00000004
#define PTHREAD_ATTR_FLAG_EXPLICIT 0x00000008
#define PTHREAD_ATTR_FLAG_SHADOW 0x00010000

// SCHED need to keep with hongmeng kernel.
#define SCHED_NORMAL 0

#ifdef __LP64__
#define __convert2uint64(ptr) ((uint64_t)(uintptr_t)(ptr));
#else
#define __convert2uint64(ptr) ((uint64_t)(uintptr_t)(ptr) & 0xFFFFFFFFULL)
#endif

static inline void *__convert2ptr(uintptr_t addr)
{
	return (void *)addr;
}

enum start_args {
	START_ARGS_ARGV = 0,
	START_ARGS_ENVP,
	START_ARGS_PARATBL
};
enum start_dyn_param {
	PARA_RANDOM = 0,
	PARA_AUXH_BASE,
	PARA_AUX_PHDR,
	PARA_AUX_PHNUM,
	PARA_AUX_PHENT,
	PARA_TCB_CREF,
	PARA_SYSMGR_CREF,
	PARA_END
};
#define MODEL32_TCB_REF_HIG	PARA_SYSMGR_CREF
#define MODEL32_TCB_REF_LOW	PARA_TCB_CREF

__attribute__((__visibility__("hidden"))) int __pthread_attr_copy(pthread_attr_t *a, const pthread_attr_t *b);
cref_t pthread_get_sysmgrch_np(pthread_t thread);
void __pthread_tsd_run_dtors();
#endif
