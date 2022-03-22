#ifndef _HISI_BOOT_H_
#define _HISI_BOOT_H_

#include <stdbool.h>

typedef signed char s8;
typedef unsigned char u8;

typedef signed short s16;
typedef unsigned short u16;

typedef signed int s32;
typedef unsigned int u32;

typedef signed long long s64;
typedef unsigned long long u64;

#define BIT(nr) (1UL << (nr))

#define hisi_udelay(usec)                                                      \
	do {                                                                   \
		int i;                                                         \
		for (i = 0; i < 500 * usec; i++) {                             \
			asm("nop");                                            \
		};                                                             \
	} while (0)

static inline void HISI_DWB(void) /* drain write buffer */
{
	asm volatile("dsb");
}

static inline void hisi_writel(unsigned val, unsigned addr)
{
	HISI_DWB();
	(*(volatile unsigned *)(addr)) = (val);
	HISI_DWB();
}

static inline void hisi_writew(unsigned val, unsigned addr)
{
	HISI_DWB();
	(*(volatile unsigned short *)(addr)) = (val);
	HISI_DWB();
}

static inline void hisi_writeb(unsigned val, unsigned addr)
{
	HISI_DWB();
	(*(volatile unsigned char *)(addr)) = (val);
	HISI_DWB();
}

static inline unsigned hisi_readl(unsigned addr)
{
	return (*(volatile unsigned *)(addr));
}

static inline unsigned hisi_readw(unsigned addr)
{
	return (*(volatile unsigned short *)(addr));
}

static inline unsigned char hisi_readb(unsigned addr)
{
	return (*(volatile unsigned char *)(addr));
}

static inline void hisi_clr_bit(unsigned val, unsigned bit)
{
	(val) = (val & (~(1 << bit)));
}

static inline void hisi_set_bit(unsigned val, unsigned bit)
{
	(val) = (val | (1 << bit));
}

struct list_head {
	struct list_head *next, *prev;
};

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(
	struct list_head *new, struct list_head *prev, struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}
static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

#endif
