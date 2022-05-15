#include <stddef.h>
#include "dynlink.h"

#ifndef START
#define START "_dlstart"
#endif

#define SHARED

#include "crt_arch.h"

#ifndef GETFUNCSYM
#define GETFUNCSYM(fp, sym, got) do { \
	__attribute__((__visibility__("hidden"))) void sym(); \
	static void (*static_func_ptr)() = sym; \
	__asm__ __volatile__ ("" : "+m" (static_func_ptr) : : "memory"); \
	*(fp) = static_func_ptr; } while (0)
#endif

__attribute__((__visibility__("hidden")))
void _dlstart_c(size_t *sp, size_t *dynv)
{
	size_t i, dyn[DYN_CNT];
	size_t *rel = NULL;
	size_t rel_size, base;

	size_t *paratbl = (void *)(uintptr_t)sp[2];

	for (i = 0; i < DYN_CNT; i++)
		dyn[i] = 0;
	for (i = 0; dynv[i]; i += 2) {
		if (dynv[i] < DYN_CNT)
			dyn[dynv[i]] = dynv[i + 1];
	}

	/* If the dynamic linker is invoked as a command, its load
	 * address is not available in the aux vector. Instead, compute
	 * the load address as the difference between &_DYNAMIC and the
	 * virtual address in the PT_DYNAMIC program header. */
	base = paratbl[1];
	if (!base) {
		/* Do not support this case */
		__builtin_trap();
	}

	rel = (void *)(uintptr_t)(base + dyn[DT_REL]);
	rel_size = dyn[DT_RELSZ];
	for (; rel_size; rel += 2, rel_size -= 2 * sizeof(size_t)) {
		if (!IS_RELATIVE(rel[1], 0)) continue;
		size_t *rel_addr = (void *)(uintptr_t)(base + rel[0]);
		*rel_addr += base;
	}

	rel = (void *)(uintptr_t)(base + dyn[DT_RELA]);
	rel_size = dyn[DT_RELASZ];
	for (; rel_size; rel += 3, rel_size -= 3 * sizeof(size_t)) {
		if (!IS_RELATIVE(rel[1], 0)) continue;
		size_t *rel_addr = (void *)(uintptr_t)(base + rel[0]);
		*rel_addr = base + rel[2];
	}

	stage2_func dls2;
	GETFUNCSYM(&dls2, __dls2, base+dyn[DT_PLTGOT]);
	dls2((void *)(uintptr_t)base, sp);
}
