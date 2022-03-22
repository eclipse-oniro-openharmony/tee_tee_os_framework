#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <elf.h>
#include <sys/mman.h>
#include <limits.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <link.h>
#include <setjmp.h>
#include <pthread.h>
#include <ctype.h>
#include <dlfcn.h>
#include <procmgr.h>
#include <mmgrapi.h>
#include <cs.h>
#include <hmlog.h>
#include <hm_thread.h>
#include <syminfo.h>
#include <sys/kuapi.h>
#include <sys/hmapi.h>
#include "pthread_impl.h"
#include "libc.h"
#include "dynlink.h"

#define RTLD_TA 0x100000

extern uintptr_t __stack_chk_guard;

static void error(const char *, ...);

#define MAXP2(a, b) (-(-(a) & -(b)))
#define ALIGN(x, y) ((x) + (y) - 1 & -(y))

struct debug {
	int ver;
	void *head;
	void (*bp)(void);
	int state;
	void *base;
};

struct dso {
	unsigned char *base;
	char *name;
	size_t *dynv;
	struct dso *next, *prev;

	Phdr *phdr;
	int phnum;
	size_t phentsize;
	Sym *syms;
	size_t syment;
	Elf_Symndx *hashtab;
	uint32_t *ghashtab;
	int16_t *versym;
	char *strings;
	size_t strtab_len;
	struct dso *syms_next, *lazy_next;
	size_t *lazy, lazy_cnt;
	unsigned char *map;
	size_t map_len;
	char relocated;
	char constructed;
	char kernel_mapped;
	char syms_filled;
	char by_dlopen;
	struct dso **deps, *needed_by;
	size_t relro_start, relro_end;
	struct dso *fini_next;
	size_t *got;
	char buf[];
};

struct symdef {
	Sym *sym;
	struct dso *dso;
};

#define ADDEND_LIMIT 4096
static size_t *saved_addends, *apply_addends_to;

static int during_dls2;
static struct dso ldso;
static struct dso *head, *tail, *fini_head, *syms_tail, *lazy_head;
static struct dso *libtee;
static unsigned long long gencnt;
static int runtime;
static int ldso_fail;
static int noload;
static int load_ta;
static jmp_buf *rtld_fail;
static pthread_rwlock_t lock;
static struct debug debug;
static struct dso *const nodeps_dummy;

struct debug *_dl_debug_addr = &debug;

static int dl_strcmp(const char *l, const char *r)
{
	for (; *l == *r && *l; l++, r++);
	return *(unsigned char *)l - *(unsigned char *)r;
}

#define strcmp(l, r) dl_strcmp(l, r)

/* Compute load address for a virtual address in a given dso. */
#define laddr(p, v) (void *)((p)->base + (v))
#define fpaddr(p, v) ((void (*)())laddr(p, v))

static void decode_vec(const size_t *v, size_t *a, size_t cnt)
{
	size_t i;
	for (i = 0; i < cnt; i++)
		a[i] = 0;
	for (; v[0]; v += 2) {
		if (v[0] - 1 < cnt - 1) {
			a[0] |= 1UL << v[0];
			a[v[0]] = v[1];
		}
	}
}

static int search_vec(const size_t *v, size_t *r, size_t key)
{
	for (; v[0] != key; v += 2)
		if (!v[0]) return 0;
	*r = v[1];
	return 1;
}

static uint32_t sysv_hash(const char *s0)
{
	const unsigned char *s = (void *)s0;
	uint_fast32_t h = 0;
	while (*s) {
		h = 16 * h + *s++;
		h ^= h >> 24 & 0xf0;
	}
	return h & 0xfffffff;
}

static uint32_t gnu_hash(const char *s0)
{
	const unsigned char *s = (void *)s0;
	uint_fast32_t h = 5381;
	for (; *s; s++)
		h += h * 32 + *s;
	return h;
}

static Sym *sysv_lookup(const char *s, uint32_t h, const struct dso *dso)
{
	size_t i;
	Sym *syms = dso->syms;
	Elf_Symndx *hashtab = dso->hashtab;
	char *strings = dso->strings;
	for (i = hashtab[2 + h % hashtab[0]]; i; i = hashtab[2 + hashtab[0] + i]) {
		if ((dso->versym == NULL || dso->versym[i] >= 0)
		    && (!strcmp(s, strings + syms[i].st_name)))
			return syms + i;
	}
	return 0;
}

static Sym *gnu_lookup(uint32_t h1, uint32_t *hashtab, const struct dso *dso, const char *s)
{
	uint32_t nbuckets = hashtab[0];
	uint32_t *buckets = hashtab + 4 + hashtab[2] * (sizeof(size_t) / 4);
	uint32_t i = buckets[h1 % nbuckets];

	if (!i) return 0;

	uint32_t *hashval = buckets + nbuckets + (i - hashtab[1]);

	for (h1 |= 1; ; i++) {
		uint32_t h2 = *hashval++;
		if ((h1 == (h2 | 1)) && (dso->versym == NULL || dso->versym[i] >= 0)
		    && !strcmp(s, dso->strings + dso->syms[i].st_name))
			return dso->syms + i;
		if (h2 & 1) break;
	}

	return 0;
}

static Sym *gnu_lookup_filtered(uint32_t h1, uint32_t *hashtab, const struct dso *dso,
				const char *s, uint32_t fofs, size_t fmask)
{
	const size_t *bloomwords = (const void *)(hashtab + 4);
	size_t f = bloomwords[fofs & (hashtab[2] - 1)];
	if (!(f & fmask)) return 0;

	f >>= (h1 >> hashtab[3]) % (8 * sizeof f);
	if (!(f & 1)) return 0;

	return gnu_lookup(h1, hashtab, dso, s);
}

#define OK_TYPES (1<<STT_NOTYPE | 1<<STT_OBJECT | 1<<STT_FUNC | 1<<STT_COMMON | 1<<STT_TLS)
#define OK_BINDS (1<<STB_GLOBAL | 1<<STB_WEAK | 1<<STB_GNU_UNIQUE)

#ifndef ARCH_SYM_REJECT_UND
#define ARCH_SYM_REJECT_UND(s) 0
#endif

static struct symdef find_sym(struct dso *dso, const char *s, int need_def)
{
	uint32_t h = 0;
	uint32_t gh = gnu_hash(s);
	uint32_t gho = gh / (8 * sizeof(size_t));
	uint32_t *ght = NULL;
	size_t ghm = 1ul << gh % (8 * sizeof(size_t));
	struct symdef def = {0};
	for (; dso; dso = dso->syms_next) {
		Sym *sym = NULL;
		ght = dso->ghashtab;
		if (ght != NULL) {
			sym = gnu_lookup_filtered(gh, ght, dso, s, gho, ghm);
		} else {
			if (!h)
				h = sysv_hash(s);
			sym = sysv_lookup(s, h, dso);
		}
		if (sym == NULL)
			continue;
		if (!sym->st_shndx)
			if (need_def || (sym->st_info & 0xf) == STT_TLS
			    || ARCH_SYM_REJECT_UND(sym))
				continue;
		if (!sym->st_value)
			if ((sym->st_info & 0xf) != STT_TLS)
				continue;
		if (!(1 << (sym->st_info & 0xf) & OK_TYPES)) continue;
		if (!(1 << (sym->st_info >> 4) & OK_BINDS)) continue;
		def.sym = sym;
		def.dso = dso;
		break;
	}
	return def;
}

static void do_relocs(struct dso *dso, size_t *rel, size_t rel_size, size_t stride)
{
	unsigned char *base = dso->base;
	Sym *syms = dso->syms;
	char *strings = dso->strings;
	Sym *sym = NULL;
	const char *name = NULL;
	void *ctx = NULL;
	int type;
	int sym_index;
	struct symdef def;
	size_t *reloc_addr = NULL;
	uintptr_t sym_val;
	size_t addend;
	int skip_relative = 0;
	int reuse_addends = 0;
	int save_slot = 0;

	if (dso == &ldso) {
		/* Only ldso's REL table needs addend saving/reuse. */
		if (rel == apply_addends_to)
			reuse_addends = 1;
		skip_relative = 1;
	}

	for (; rel_size; rel += stride, rel_size -= stride * sizeof(size_t)) {
		if (skip_relative && IS_RELATIVE(rel[1], dso->syms)) continue;
		type = R_TYPE(rel[1]);
		if (type == REL_NONE) continue;
		reloc_addr = laddr(dso, rel[0]);

		if (stride > 2) {
			addend = rel[2];
		} else if (type == REL_GOT || type == REL_PLT || type == REL_COPY) {
			addend = 0;
		} else if (reuse_addends) {
			/* Save original addend in stage 2 where the dso
			 * chain consists of just ldso; otherwise read back
			 * saved addend since the inline one was clobbered. */
			if (head == &ldso)
				saved_addends[save_slot] = *reloc_addr;
			addend = saved_addends[save_slot++];
		} else {
			addend = *reloc_addr;
		}

		sym_index = R_SYM(rel[1]);
		if (sym_index) {
			sym = syms + sym_index;
			name = strings + sym->st_name;
			ctx = type == REL_COPY ? head->syms_next : head;
			if ((sym->st_info & 0xf) == STT_SECTION) {
				def = (struct symdef){ .dso = dso, .sym = sym };
			} else if (load_ta) {
				def = find_sym(dso, name, type == REL_PLT);
				if (def.sym == NULL && libtee)
					def = find_sym(libtee, name, type == REL_PLT);
				if (def.sym == NULL)
					def = find_sym(ctx, name, type == REL_PLT);
			} else {
				def = find_sym(ctx, name, type == REL_PLT);
			}
			if (def.sym == NULL && (sym->st_shndx != SHN_UNDEF
			    || sym->st_info >> 4 != STB_WEAK)) {
				if (dso->lazy && (type == REL_PLT || type == REL_GOT)) {
					dso->lazy[3 * dso->lazy_cnt + 0] = rel[0];
					dso->lazy[3 * dso->lazy_cnt + 1] = rel[1];
					dso->lazy[3 * dso->lazy_cnt + 2] = addend;
					dso->lazy_cnt++;
					continue;
				}
				/* A hack for undefined symbols in libc.so */
				if (during_dls2)
					continue;
				error("Error relocating %s: %s: symbol not found",
					dso->name, name);
				if (runtime) longjmp(*rtld_fail, 1);
				continue;
			}
		} else {
			sym = 0;
			def.sym = 0;
			def.dso = dso;
		}

		sym_val = def.sym ? (uintptr_t)laddr(def.dso, def.sym->st_value) : 0;

		/* Check reloc_addr validity */
		switch (type) {
		case REL_OFFSET:
		case REL_SYMBOLIC:
		case REL_GOT:
		case REL_PLT:
		case REL_RELATIVE:
		case REL_SYM_OR_REL:
			if (rel[0] + sizeof(size_t) < rel[0]
			    || rel[0] + sizeof(size_t) > dso->map_len) {
				error("Error relocating %s: invalid reloc_addr", dso->name);
				if (runtime)
					longjmp(*rtld_fail, 1);
			}
			break;
		case REL_OFFSET32:
			if (rel[0] + sizeof(uint32_t) < rel[0]
			    || rel[0] + sizeof(uint32_t) > dso->map_len) {
				error("Error relocating %s: invalid reloc_addr", dso->name);
				if (runtime)
					longjmp(*rtld_fail, 1);
			}
			break;
		case REL_COPY:
			if (sym == NULL || rel[0] + sym->st_size < rel[0]
			    || rel[0] + sym->st_size > dso->map_len) {
				error("Error relocating %s: invalid reloc_addr", dso->name);
				if (runtime)
					longjmp(*rtld_fail, 1);
			}
			break;
		}

		switch (type) {
		case REL_OFFSET:
			addend -= (uintptr_t)reloc_addr;
			/* fall through */
		case REL_SYMBOLIC:
		case REL_GOT:
		case REL_PLT:
			*reloc_addr = sym_val + addend;
			break;
		case REL_RELATIVE:
			*reloc_addr = (uintptr_t)base + addend;
			break;
		case REL_SYM_OR_REL:
			if (sym != NULL)
				*reloc_addr = sym_val + addend;
			else
				*reloc_addr = (uintptr_t)base + addend;
			break;
		case REL_COPY:
			if (sym == NULL)
				break;
			for (size_t i = 0; i < sym->st_size; ++i)
				((char *)reloc_addr)[i] = ((char *)sym_val)[i];
			break;
		case REL_OFFSET32:
			*(uint32_t *)reloc_addr = sym_val + addend
				- (uintptr_t)reloc_addr;
			break;
		default:
			error("Error relocating %s: unsupported relocation type %d",
				dso->name, type);
			if (runtime) longjmp(*rtld_fail, 1);
			continue;
		}
	}
}

static void redo_lazy_relocs()
{
	struct dso *p = lazy_head;
	struct dso *next = NULL;
	lazy_head = 0;
	for (; p; p = next) {
		next = p->lazy_next;
		size_t size = p->lazy_cnt * 3 * sizeof(size_t);
		p->lazy_cnt = 0;
		do_relocs(p, p->lazy, size, 3);
		if (p->lazy_cnt) {
			p->lazy_next = lazy_head;
			lazy_head = p;
		} else {
			free(p->lazy);
			p->lazy = 0;
			p->lazy_next = 0;
		}
	}
}

static void unmap_library(struct dso *dso)
{
	if (dso->map && dso->map_len) {
		munmap(dso->map, dso->map_len);
	}
}

static void *map_library(const char *name, struct dso *dso)
{
	size_t phsize;
	size_t addr_min = SIZE_MAX;
	size_t addr_max = 0;
	size_t map_len = 0;
	size_t nsegs = 0;
	off_t off_start = 0;
	Ehdr *eh = NULL;
	Phdr *ph = NULL;
	Phdr *ph0 = NULL;
	unsigned char *map = NULL;
	unsigned char *base = NULL;
	size_t dyn = 0;
	size_t i;

	map = hm_map_library(name, &map_len);
	if (map == MAP_FAILED)
		return 0;

	eh = (Ehdr *)map;
	if (eh->e_type != ET_DYN)
		goto noexec;
	phsize = (uint32_t)eh->e_phentsize * (uint32_t)eh->e_phnum;
	ph = ph0 = (void *)(map + eh->e_phoff);

	for (i = eh->e_phnum; i; i--, ph = (void *)((char *)ph + eh->e_phentsize)) {
		if (ph->p_type == PT_DYNAMIC) {
			dyn = ph->p_vaddr;
		} else if (ph->p_type == PT_TLS) {
			/* Do not support this case */
			error("PT_TLS not supported\n");
			goto error;
		} else if (ph->p_type == PT_GNU_RELRO) {
			dso->relro_start = ph->p_vaddr & -PAGE_SIZE;
			dso->relro_end = (ph->p_vaddr + ph->p_memsz) & -PAGE_SIZE;
		}
		if (ph->p_type != PT_LOAD) continue;
		nsegs++;
		if (ph->p_vaddr < addr_min) {
			addr_min = ph->p_vaddr;
			off_start = ph->p_offset;
		}
		if (ph->p_vaddr + ph->p_memsz > addr_max) {
			addr_max = ph->p_vaddr + ph->p_memsz;
		}
	}
	if (!dyn) goto noexec;
	addr_max += PAGE_SIZE - 1;
	addr_max &= -PAGE_SIZE;
	addr_min &= -PAGE_SIZE;
	off_start &= -PAGE_SIZE;

	dso->map = map;
	dso->map_len = map_len;
	/* sysmgr guarantees off_start = addr_min = 0 */
	base = map + off_start - addr_min;
	dso->phdr = 0;
	dso->phnum = 0;
	for (ph = ph0, i = eh->e_phnum; i; i--, ph = (void *)((char *)ph + eh->e_phentsize)) {
		if (ph->p_type != PT_LOAD) continue;
		/* Check if the programs headers are in this load segment, and
		 * if so, record the address for use by dl_iterate_phdr. */
		if (dso->phdr == NULL && eh->e_phoff >= ph->p_offset
		    && eh->e_phoff + phsize <= ph->p_offset + ph->p_filesz) {
			dso->phdr = (void *)(base + ph->p_vaddr
				+ (eh->e_phoff-ph->p_offset));
			dso->phnum = eh->e_phnum;
			dso->phentsize = eh->e_phentsize;
		}
	}
	for (i = 0; ((size_t *)(base + dyn))[i]; i += 2)
		if (((size_t *)(base + dyn))[i] == DT_TEXTREL) {
			/* Do not support this case */
			error("DT_TEXTREL not supported\n");
			goto error;
		}
	dso->base = base;
	dso->dynv = laddr(dso, dyn);
	return map;
noexec:
	errno = ENOEXEC;
error:
	if (map != MAP_FAILED) unmap_library(dso);
	return 0;
}

static void decode_dyn(struct dso *p)
{
	size_t dyn[DYN_CNT];
	decode_vec(p->dynv, dyn, DYN_CNT);
	p->syms = laddr(p, dyn[DT_SYMTAB]);
	p->syment = dyn[DT_SYMENT];
	p->strings = laddr(p, dyn[DT_STRTAB]);
	p->strtab_len = dyn[DT_STRSZ];
	if (dyn[0] & (1 << DT_HASH))
		p->hashtab = laddr(p, dyn[DT_HASH]);
	if (dyn[0] & (1 << DT_PLTGOT))
		p->got = laddr(p, dyn[DT_PLTGOT]);
	if (search_vec(p->dynv, dyn, DT_GNU_HASH))
		p->ghashtab = laddr(p, *dyn);
	if (search_vec(p->dynv, dyn, DT_VERSYM))
		p->versym = laddr(p, *dyn);
}

static size_t count_syms(const struct dso *p)
{
	if (p->hashtab != NULL) return p->hashtab[1];

	size_t nsym, i;
	uint32_t *buckets = p->ghashtab + 4 + (p->ghashtab[2] * sizeof(size_t) / 4);
	uint32_t *hashval = NULL;
	for (i = nsym = 0; i < p->ghashtab[0]; i++) {
		if (buckets[i] > nsym)
			nsym = buckets[i];
	}
	if (nsym) {
		hashval = buckets + p->ghashtab[0] + (nsym - p->ghashtab[1]);
		do nsym++;
		while (!(*hashval++ & 1));
	}
	return nsym;
}

static void fill_syminfo(struct dso *p)
{
	size_t i;

	if (p->syms_filled)
		return;

    uint64_t si_vaddr = hmapi_cnode_sivaddr();
    if (si_vaddr == INVALID_CNODE_SIVADDR) {
        hm_error("hmapi_cnode_sivaddr failed.\n");
        return;
    }
	/* Fill hm_syminfo structure */
	for (i = 0; i < SYMINFO_PER_PAGE; ++i) {
		struct hm_syminfo *si = (struct hm_syminfo*)si_vaddr + i;
		if (si->symtab_addr)
			continue;
		si->symtab_addr = (uintptr_t)p->syms;
		si->symtab_len = (uint64_t)p->syment * count_syms(p);
		si->strtab_addr = (uintptr_t)p->strings;
		si->strtab_len = p->strtab_len;
		si->sym_offset = (uintptr_t)p->base;
		p->syms_filled = 1;
		break;
	}

	if (!p->syms_filled)
		hm_error("%s: syminfo not loaded\n", p->name);
}

static struct dso *load_library(const char *name, struct dso *needed_by)
{
	unsigned char *map = NULL;
	struct dso *p = NULL;
	struct dso temp_dso = {0};
	size_t alloc_size;
	int is_self = 0;

	if (!*name) {
		errno = EINVAL;
		return 0;
	}

	if (!strcmp(name, ldso.name))
		is_self = 1;
	if (is_self) {
		if (ldso.prev == NULL) {
			tail->next = &ldso;
			ldso.prev = tail;
			tail = &ldso;
		}
		return &ldso;
	}

	for (p = head->next; p; p = p->next) {
		if (!strcmp(p->name, name))
			return p;
	}
	map = noload ? 0 : map_library(name, &temp_dso);
	if (map == NULL) return 0;

	decode_dyn(&temp_dso);

	/* Allocate storage for the new DSO. */
	alloc_size = sizeof *p + strlen(name) + 1;
	p = calloc(1, alloc_size);
	if (p == NULL) {
		unmap_library(&temp_dso);
		return 0;
	}
	for (size_t i = 0; i < sizeof *p; ++i)
		((char *)p)[i] = ((char *)&temp_dso)[i];
	for (size_t i = sizeof *p; i < alloc_size; ++i)
		((char *)p)[i] = name[i - sizeof *p];
	p->needed_by = needed_by;
	p->name = p->buf;
	if (runtime)
		p->by_dlopen = 1;

	tail->next = p;
	p->prev = tail;
	tail = p;
	fill_syminfo(p);

	return p;
}

static void load_deps(struct dso *p)
{
	size_t i;
	size_t ndeps=0;
	struct dso ***deps = &p->deps;
	struct dso **tmp = NULL;
	struct dso *dep = NULL;
	for (; p; p = p->next) {
		for (i = 0; p->dynv[i]; i += 2) {
			if (p->dynv[i] != DT_NEEDED) continue;
			dep = load_library(p->strings + p->dynv[i + 1], p);
			if (dep == NULL) {
				error("Error loading shared library %s: %m (needed by %s)",
					p->strings + p->dynv[i + 1], p->name);
				if (runtime) longjmp(*rtld_fail, 1);
				continue;
			}
			if (runtime) {
				tmp = realloc(*deps, sizeof(*tmp) * (ndeps + 2));
				if (tmp == NULL) longjmp(*rtld_fail, 1);
				tmp[ndeps++] = dep;
				tmp[ndeps] = 0;
				*deps = tmp;
			}
		}
	}
	if (!*deps) *deps = (struct dso **)&nodeps_dummy;
}

static void add_syms(struct dso *p)
{
	if (p->syms_next == NULL && syms_tail != p) {
		syms_tail->syms_next = p;
		syms_tail = p;
	}
}

static void revert_syms(struct dso *old_tail)
{
	struct dso *p = NULL;
	struct dso *next = NULL;
	/* Chop off the tail of the list of dsos that participate in
	 * the global symbol table, reverting them to RTLD_LOCAL. */
	for (p = old_tail; p; p = next) {
		next = p->syms_next;
		p->syms_next = 0;
	}
	syms_tail = old_tail;
}

static void reloc_all(struct dso *p)
{
	size_t dyn[DYN_CNT];
	for (; p; p = p->next) {
		if (p->relocated) continue;
		decode_vec(p->dynv, dyn, DYN_CNT);
		do_relocs(p, laddr(p, dyn[DT_JMPREL]), dyn[DT_PLTRELSZ],
			(dyn[DT_PLTREL] == DT_RELA) + 2);
		do_relocs(p, laddr(p, dyn[DT_REL]), dyn[DT_RELSZ], 2);
		do_relocs(p, laddr(p, dyn[DT_RELA]), dyn[DT_RELASZ], 3);

		if (head != &ldso && p->relro_start != p->relro_end &&
		    mprotect(laddr(p, p->relro_start), p->relro_end - p->relro_start, PROT_READ)
		    && errno != ENOSYS) {
			error("Error relocating %s: RELRO protection failed: %m",
				p->name);
			if (runtime) longjmp(*rtld_fail, 1);
		}

		p->relocated = 1;
	}
}

static void kernel_mapped_dso(struct dso *p)
{
	size_t min_addr = -1;
	size_t max_addr = 0;
	size_t cnt;
	Phdr *ph = p->phdr;
	for (cnt = p->phnum; cnt--; ph = (void *)((char *)ph + p->phentsize)) {
		if (ph->p_type == PT_DYNAMIC) {
			p->dynv = laddr(p, ph->p_vaddr);
		} else if (ph->p_type == PT_GNU_RELRO) {
			p->relro_start = ph->p_vaddr & -PAGE_SIZE;
			p->relro_end = (ph->p_vaddr + ph->p_memsz) & -PAGE_SIZE;
		}
		if (ph->p_type != PT_LOAD) continue;
		if (ph->p_vaddr < min_addr)
			min_addr = ph->p_vaddr;
		if (ph->p_vaddr + ph->p_memsz > max_addr)
			max_addr = ph->p_vaddr + ph->p_memsz;
	}
	min_addr &= -PAGE_SIZE;
	max_addr = (max_addr + PAGE_SIZE - 1) & -PAGE_SIZE;
	p->map = p->base + min_addr;
	p->map_len = max_addr - min_addr;
	p->kernel_mapped = 1;
}

void __libc_exit_fini()
{
	struct dso *p = NULL;
	size_t dyn[DYN_CNT];
	for (p = fini_head; p; p = p->fini_next) {
		if (!p->constructed) continue;
		decode_vec(p->dynv, dyn, DYN_CNT);
		if (dyn[0] & (1 << DT_FINI_ARRAY)) {
			size_t n = dyn[DT_FINI_ARRAYSZ] / sizeof(size_t);
			uintptr_t *fn = (uintptr_t *)laddr(p, dyn[DT_FINI_ARRAY]) + n;
			while (n--) ((void (*)(void))*--fn)();
		}
#ifndef NO_LEGACY_INITFINI
		if ((dyn[0] & (1 << DT_FINI)) && dyn[DT_FINI])
			fpaddr(p, dyn[DT_FINI])();
#endif
	}
}

static void do_init_fini(struct dso *p)
{
	size_t dyn[DYN_CNT];

	for (; p; p = p->prev) {
		if (p->constructed) continue;
		p->constructed = 1;
		decode_vec(p->dynv, dyn, DYN_CNT);
		if (dyn[0] & ((1 << DT_FINI) | (1 << DT_FINI_ARRAY))) {
			p->fini_next = fini_head;
			fini_head = p;
		}
#ifndef NO_LEGACY_INITFINI
		if ((dyn[0] & (1 << DT_INIT)) && dyn[DT_INIT])
			fpaddr(p, dyn[DT_INIT])();
#endif
		if (dyn[0] & (1 << DT_INIT_ARRAY)) {
			size_t n = dyn[DT_INIT_ARRAYSZ] / sizeof(size_t);
			uintptr_t *fn = laddr(p, dyn[DT_INIT_ARRAY]);
			while (n--) ((void (*)(void))*fn++)();
		}
	}
}

void __libc_start_init(void)
{
	do_init_fini(tail);
}

static void dl_debug_state(void)
{
}

weak_alias(dl_debug_state, _dl_debug_state);

/* Stage 1 of the dynamic linker is defined in dlstart.c. It calls the
 * following stage 2 and stage 3 functions via primitive symbolic lookup
 * since it does not have access to their addresses to begin with.
 *
 * Stage 2 of the dynamic linker is called after relative relocations
 * have been processed. It can make function calls to static functions
 * and access string literals and static data, but cannot use extern
 * symbols. Its job is to perform symbolic relocations on the dynamic
 * linker itself, but some of the relocations performed may need to be
 * replaced later due to copy relocations in the main program.
 */
__attribute__((__visibility__("hidden")))
void __dls2(unsigned char *base, size_t *sp)
{
	ldso.base = base;
	Ehdr *ehdr = (void *)ldso.base;
#ifdef __aarch64__
	ldso.name = "libc_shared.so";
#else
	ldso.name = "libc_shared_a32.so";
#endif
	ldso.phnum = ehdr->e_phnum;
	ldso.phdr = laddr(&ldso, ehdr->e_phoff);
	ldso.phentsize = ehdr->e_phentsize;
	kernel_mapped_dso(&ldso);
	decode_dyn(&ldso);

	/* Prepare storage for to save clobbered REL addends so they
	 * can be reused in stage 3. There should be very few. If
	 * something goes wrong and there are a huge number, abort
	 * instead of risking stack overflow. */
	size_t dyn[DYN_CNT];
	decode_vec(ldso.dynv, dyn, DYN_CNT);
	size_t *rel = laddr(&ldso, dyn[DT_REL]);
	size_t rel_size = dyn[DT_RELSZ];
	size_t symbolic_rel_cnt = 0;
	apply_addends_to = rel;
	for (; rel_size; rel += 2, rel_size -= 2 * sizeof(size_t))
		if (!IS_RELATIVE(rel[1], ldso.syms)) symbolic_rel_cnt++;
	if (symbolic_rel_cnt >= ADDEND_LIMIT) a_crash();
	size_t addends[symbolic_rel_cnt + 1];
	saved_addends = addends;

	head = &ldso;
	/* A hack for undefined symbols in libc.so */
	during_dls2 = 1;
	reloc_all(&ldso);
	during_dls2 = 0;

	ldso.relocated = 0;

	/* Call dynamic linker stage-3, __dls3, looking it up
	 * symbolically as a barrier against moving the address
	 * load across the above relocation processing. */
	struct symdef dls3_def = find_sym(&ldso, "__dls3", 0);
	((stage3_func)laddr(&ldso, dls3_def.sym->st_value))(sp);
}

/* Stage 3 of the dynamic linker is called with the dynamic linker/libc
 * fully functional. Its job is to load (if not already loaded) and
 * process dependencies and relocations for the main application and
 * transfer control to its entry point. */

_Noreturn void __dls3(size_t *sp)
{
	static struct dso app;
	size_t i;
	int argc = (int)((sp[START_ARGS_ENVP] - sp[START_ARGS_ARGV]) / sizeof(void *)) - 1;
	char **argv = (void *)(uintptr_t)sp[START_ARGS_ARGV];
	char **envp = (void *)(uintptr_t)sp[START_ARGS_ENVP];
	size_t *paratbl = (void *)(uintptr_t)sp[START_ARGS_PARATBL];
	int ret;

	/* Early initialization */
	environ = envp;
#ifdef CONFIG_CC_STACKPROTECTOR
	__stack_chk_guard = paratbl[PARA_RANDOM];
#endif
#ifdef __LP64__
	__tcb_cref.tcb = paratbl[PARA_TCB_CREF];
	__sysmgrch = paratbl[PARA_SYSMGR_CREF];
#else
	/* Little-endian */
	__tcb_cref.tcb = ((uint64_t)paratbl[MODEL32_TCB_REF_HIG] << 32) | paratbl[MODEL32_TCB_REF_LOW];
	__sysmgrch = pthread_get_sysmgrch();
#endif
	hm_mmgr_clt_init();
	if (cs_client_init(&g_sysmgr_client, __sysmgrch))
		hm_panic("dynlink: cs_client_init failed\n");

	/* Setup early thread pointer in builtin_tls for ldso/libc itself to
	 * use during dynamic linking. If possible it will also serve as the
	 * thread pointer at runtime. */

	__libc_init_tls();

	/* app's syminfo is loaded by procmgr */
	app.syms_filled = 1;

	/* If the main program was already loaded by the kernel,
	 * AT_PHDR will point to some location other than the dynamic
	 * linker's program headers. */
	if (paratbl[PARA_AUX_PHDR] != (uintptr_t)ldso.phdr) {
		size_t interp_off = 0;
		/* Find load address of the main program, via AT_PHDR vs PT_PHDR. */
		Phdr *phdr = app.phdr = (void *)(uintptr_t)paratbl[PARA_AUX_PHDR];
		app.phnum = paratbl[PARA_AUX_PHNUM];
		app.phentsize = paratbl[PARA_AUX_PHENT];
		for (i=paratbl[PARA_AUX_PHNUM]; i; i--, phdr=(void *)((char *)phdr + paratbl[PARA_AUX_PHENT])) {
			if (phdr->p_type == PT_PHDR)
				app.base = (void *)(uintptr_t)(paratbl[PARA_AUX_PHDR] - phdr->p_vaddr);
			else if (phdr->p_type == PT_INTERP)
				interp_off = (size_t)phdr->p_vaddr;
			else if (phdr->p_type == PT_TLS) {
				/* Do not support TLS section */
				hm_panic("dynlink: PT_TLS unsupported\n");
			}
		}
		if (interp_off)
			ldso.name = laddr(&app, interp_off);
		app.name = argv[0];
		kernel_mapped_dso(&app);
	} else {
		/* Do not support this case */
		hm_panic("dynlink: main program not loaded\n");
	}
	decode_dyn(&app);

	/* Initial dso chain consists only of the app. */
	head = tail = syms_tail = &app;

	/* Load needed libraries, add symbols to global namespace. */
   load_deps(&app);
	for (struct dso *p = head; p; p = p->next) {
		add_syms(p);
		fill_syminfo(p);
	}

	for (i = 0; app.dynv[i]; i += 2) {
		if (app.dynv[i] == DT_DEBUG)
			app.dynv[i + 1] = (uintptr_t)&debug;
	}

	/* The main program must be relocated LAST since it may contin
	 * copy relocations which depend on libraries' relocations. */
	reloc_all(app.next);
	reloc_all(&app);

	if (ldso_fail) hm_exit(127);

	/* Switch to runtime mode: any further failures in the dynamic
	 * linker are a reportable failure rather than a fatal startup
	 * error. */
	runtime = 1;

	debug.ver = 1;
	debug.bp = dl_debug_state;
	debug.head = head;
	debug.base = ldso.base;
	debug.state = 0;
	_dl_debug_state();

	errno = 0;

	ret = __libc_start_main(argc, argv, envp);
	hm_exit(ret);
	while (true)
		thread_exit(NULL);
	__builtin_unreachable();
}

static void prepare_lazy(struct dso *p)
{
	size_t dyn[DYN_CNT];
	size_t n;
	size_t flags1 = 0;
	decode_vec(p->dynv, dyn, DYN_CNT);
	search_vec(p->dynv, &flags1, DT_FLAGS_1);
	if (dyn[DT_BIND_NOW] || (dyn[DT_FLAGS] & DF_BIND_NOW) || (flags1 & DF_1_NOW))
		return;
	n = dyn[DT_RELSZ] / 2 + dyn[DT_RELASZ] / 3 + dyn[DT_PLTRELSZ] / 2 + 1;
	p->lazy = calloc(n, 3 * sizeof(size_t));
	if (p->lazy == NULL) {
		error("Error preparing lazy relocation for %s: %m", p->name);
		longjmp(*rtld_fail, 1);
	}
	p->lazy_next = lazy_head;
	lazy_head = p;
}

void *dlopen(const char *file, int mode)
{
	struct dso *volatile p, *orig_tail, *orig_syms_tail, *orig_lazy_head, *next;
	size_t i;
	int cs;
	jmp_buf jb;

	if (file == NULL) return head;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cs);
	pthread_rwlock_wrlock(&lock);
	__inhibit_ptc();

	p = 0;
	orig_lazy_head = lazy_head;
	orig_syms_tail = syms_tail;
	orig_tail = tail;
	noload = mode & RTLD_NOLOAD;
	/* Special case handling for TA dynlink */
	if (mode & RTLD_TA)
		load_ta = 0x1234;

	rtld_fail = &jb;
	if (setjmp(*rtld_fail)) {
		/* Clean up anything new that was (partially) loaded */
		revert_syms(orig_syms_tail);
		for (p = orig_tail->next; p; p = next) {
			next = p->next;
			if (p->deps != &nodeps_dummy)
				free(p->deps);
			unmap_library(p);
			free(p);
		}
		lazy_head = orig_lazy_head;
		tail = orig_tail;
		tail->next = 0;
		p = 0;
		goto end;
	} else p = load_library(file, head);

	if (p == NULL) {
		error(noload ?
			"Library %s is not already loaded" :
			"Error loading shared library %s: %m",
			file);
		goto end;
	}

	/* First load handling */
	int first_load = !p->deps;
	if (first_load) {
		load_deps(p);
		if (!p->relocated && (mode & RTLD_LAZY)) {
			prepare_lazy(p);
			for (i = 0; p->deps[i]; i++)
				if (!p->deps[i]->relocated)
					prepare_lazy(p->deps[i]);
		}
	}
	if (first_load || (mode & RTLD_GLOBAL)) {
		/* Make new symbols global, at least temporarily, so we can do
		 * relocations. If not RTLD_GLOBAL, this is reverted below. */
		add_syms(p);
		for (i = 0; p->deps[i]; i++)
			add_syms(p->deps[i]);
	}
	if (first_load) {
		reloc_all(p);
	}

	/* If RTLD_GLOBAL was not specified, undo any new additions
	 * to the global symbol table. This is a nop if the library was
	 * previously loaded and already global. */
	if (!(mode & RTLD_GLOBAL))
		revert_syms(orig_syms_tail);

	/* Processing of deferred lazy relocations must not happen until
	 * the new libraries are committed; otherwise we could end up with
	 * relocations resolved to symbol definitions that get removed. */
	redo_lazy_relocs();

	_dl_debug_state();
	orig_tail = tail;
end:
	__release_ptc();
	if (p != NULL) {
		gencnt++;
		do_init_fini(orig_tail);
	}
	pthread_rwlock_unlock(&lock);
	pthread_setcancelstate(cs, 0);
	/* The first dlopen'ed library is libtee */
	if (load_ta && !libtee)
		libtee = p;
	return p;
}

__attribute__((__visibility__("hidden")))
int __dl_invalid_handle(const void *h)
{
	for (struct dso *p = head; p; p = p->next) {
		if (h == p) {
			return 0;
		}
	}
	error("Invalid library handle");
	return 1;
}

static int do_dlclose(struct dso *p)
{
	struct dso *d = NULL;
	size_t n;
    bool get_si_vaddr = true;
    uint64_t si_vaddr = hmapi_cnode_sivaddr();
    if(si_vaddr == INVALID_CNODE_SIVADDR) {
        get_si_vaddr = false;
        hm_error("hmapi_cnode_sivaddr failed.\n");
    }
	if (p == head) {
		error("Can not unload main program");
		return -1;
	}
	if (p == &ldso) {
		error("Can not unload ldso library");
		return -1;
	}
	if (__dl_invalid_handle(p))
		return -1;
	if (!p->by_dlopen) {
		error("Library %s is not loaded by dlopen", p->name);
		return -1;
	}

	if (p->constructed) {
		size_t dyn[DYN_CNT];
		decode_vec(p->dynv, dyn, DYN_CNT);
		if (dyn[0] & (1 << DT_FINI_ARRAY)) {
			n = dyn[DT_FINI_ARRAYSZ] / sizeof(size_t);
			uintptr_t *fn = (uintptr_t *)laddr(p, dyn[DT_FINI_ARRAY]) + n;
			while (n--)
				((void (*)(void))*--fn)();
		}
		p->constructed = 0;
	}

	if (p->syms_filled && get_si_vaddr) {
		struct hm_syminfo *dst = NULL, *src = NULL;
		for (n = 0; n < SYMINFO_PER_PAGE; ++n) {
			struct hm_syminfo *si = (struct hm_syminfo*)si_vaddr + n;
			if (!si->symtab_addr)
				break;
			if (si->symtab_addr == (uintptr_t)p->syms)
				dst = si;
			src = si;
		}
		if (dst == NULL)
			hm_panic("Corrupted syminfo index\n");
		if (dst != src)
			*dst = *src;
		*src = (struct hm_syminfo){0};
		p->syms_filled = 0;
	}

	if (p->syms_next != NULL) {
		for (d = head; d->syms_next != p; d = d->syms_next)
			;
		d->syms_next = p->syms_next;
	} else if (p == syms_tail) {
		for (d = head; d->syms_next != p; d = d->syms_next)
			;
		d->syms_next = NULL;
		syms_tail = d;
	}

	if (p == lazy_head) {
		lazy_head = p->lazy_next;
	} else if (p->lazy_next != NULL) {
		for (d = lazy_head; d->lazy_next != p; d = d->lazy_next)
			;
		d->lazy_next = p->lazy_next;
	}

	if (p == fini_head) {
		fini_head = p->fini_next;
	} else if (p->fini_next != NULL) {
		for (d = fini_head; d->fini_next != p; d = d->fini_next)
			;
		d->fini_next = p->fini_next;
	}

	if (p == tail) {
		tail = p->prev;
		tail->next = NULL;
	} else {
		p->next->prev = p->prev;
		p->prev->next = p->next;
	}

	free(p->lazy);
	if (p->deps != &nodeps_dummy)
		free(p->deps);
	unmap_library(p);
	free(p);

	return 0;
}

int dlclose(void *p)
{
	int rc;
	rc = pthread_rwlock_wrlock(&lock);
	if (rc)
		return rc;
	__inhibit_ptc();
	rc = do_dlclose(p);
	__release_ptc();
	(void)pthread_rwlock_unlock(&lock);
	return rc;
}

static void *addr2dso(size_t a)
{
	struct dso *p = NULL;
	for (p = head; p; p = p->next) {
		if (a - (uintptr_t)p->map < p->map_len)
			return p;
	}
	return 0;
}

static void *do_dlsym(struct dso *p, const char *s, void *ra)
{
	size_t i;
	uint32_t h = 0;
	uint32_t gh = 0;
	uint32_t *ght = NULL;
	Sym *sym = NULL;
	if (p == head || p == RTLD_DEFAULT || p == RTLD_NEXT) {
		if (p == RTLD_DEFAULT) {
			p = head;
		} else if (p == RTLD_NEXT) {
			p = addr2dso((uintptr_t)ra);
			if (p == NULL)
				p = head;
			p = p->next;
		}
		struct symdef def = find_sym(p, s, 0);
		if (def.sym == NULL) goto failed;
		if ((def.sym->st_info & 0xf) == STT_TLS) {
			/* Do not support TLS section */
			error("STT_TLS not supported: %s", s);
			return 0;
		}
		return laddr(def.dso, def.sym->st_value);
	}
	if (__dl_invalid_handle(p))
		return 0;
	ght = p->ghashtab;
	if (ght) {
		gh = gnu_hash(s);
		sym = gnu_lookup(gh, ght, p, s);
	} else {
		h = sysv_hash(s);
		sym = sysv_lookup(s, h, p);
	}
	if (sym && (sym->st_info & 0xf) == STT_TLS) {
		/* Do not support TLS section */
		error("STT_TLS not supported: %s", s);
		return 0;
	}
	if (sym && sym->st_value && (1 << (sym->st_info & 0xf) & OK_TYPES))
		return laddr(p, sym->st_value);
	for (i = 0; p->deps[i]; i++) {
		ght = p->deps[i]->ghashtab;
		if (ght) {
			if (!gh)
				gh = gnu_hash(s);
			sym = gnu_lookup(gh, ght, p->deps[i], s);
		} else {
			if (!h)
				h = sysv_hash(s);
			sym = sysv_lookup(s, h, p->deps[i]);
		}
		if (sym && (sym->st_info & 0xf) == STT_TLS) {
			/* Do not support TLS section */
			error("STT_TLS not supported: %s", s);
			return 0;
		}
		if (sym != NULL && sym->st_value && (1 << (sym->st_info & 0xf) & OK_TYPES))
			return laddr(p->deps[i], sym->st_value);
	}
failed:
	error("Symbol not found: %s", s);
	return 0;
}

int dladdr(const void *addr, Dl_info *info)
{
	struct dso *p = NULL;
	Sym *sym = NULL;
	Sym *bestsym = NULL;
	uint32_t nsym;
	char *strings = NULL;
	void *best = NULL;

	pthread_rwlock_rdlock(&lock);
	p = addr2dso((uintptr_t)addr);
	pthread_rwlock_unlock(&lock);

	if (p == NULL) return 0;

	sym = p->syms;
	strings = p->strings;
	nsym = count_syms(p);

	if (best == NULL) for (; nsym; nsym--, sym++) {
		if (sym->st_value
		 && (1 << (sym->st_info & 0xf) & OK_TYPES)
		 && (1 << (sym->st_info >> 4) & OK_BINDS)) {
			void *symaddr = laddr(p, sym->st_value);
			if (symaddr > addr || symaddr < best)
				continue;
			best = symaddr;
			bestsym = sym;
			if (addr == symaddr)
				break;
		}
	}

	if (best == NULL) return 0;

	info->dli_fname = p->name;
	info->dli_fbase = p->base;
	info->dli_sname = strings + bestsym->st_name;
	info->dli_saddr = best;

	return 1;
}

__attribute__((__visibility__("hidden")))
void *__dlsym(void *restrict p, const char *restrict s, void *restrict ra)
{
	void *res = NULL;
	pthread_rwlock_rdlock(&lock);
	res = do_dlsym(p, s, ra);
	pthread_rwlock_unlock(&lock);
	return res;
}

int dl_iterate_phdr(int(*callback)(struct dl_phdr_info *info, size_t size, void *data), void *data)
{
	struct dso *current = NULL;
	struct dl_phdr_info info;
	int ret = 0;
	for (current = head; current;) {
		info.dlpi_addr      = (uintptr_t)current->base;
		info.dlpi_name      = current->name;
		info.dlpi_phdr      = current->phdr;
		info.dlpi_phnum     = current->phnum;
		info.dlpi_adds      = gencnt;
		info.dlpi_subs      = 0;
		info.dlpi_tls_modid = 0;
		info.dlpi_tls_data  = 0;

		ret = (callback)(&info, sizeof(info), data);

		if (ret != 0) break;

		pthread_rwlock_rdlock(&lock);
		current = current->next;
		pthread_rwlock_unlock(&lock);
	}
	return ret;
}

__attribute__((__visibility__("hidden")))
void __dl_vseterr(const char *, va_list);

static void error(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (!runtime) {
		vdprintf(2, fmt, ap);
		dprintf(2, "\n");
		ldso_fail = 1;
		va_end(ap);
		return;
	}
	__dl_vseterr(fmt, ap);
	va_end(ap);
}
