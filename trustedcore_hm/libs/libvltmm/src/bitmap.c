#include "sre_typedef.h"
#include "securec.h"
#include "tee_log.h"
#include "tee_common.h"
#include "tee_internal_api.h"
#include "genalloc.h"

#define BITS_PER_CHAR 8
#define BITS_PER_LONG 32
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(end) (~0UL >> (-(end) & (BITS_PER_LONG - 1)))

#define MIN(a, b) ((a < b) ? (a) : (b))

static s32 find_first_bit(u32 word)
{
	s32 num = 0;

	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

static u32 find_next_bit(const u32 *addr, u32 end, u32 start, u32 invert)
{
	u32 tmp;

	if (!end || start >= end)
		return end;

	tmp = addr[start / BITS_PER_LONG] ^ invert;

	/* Handle 1st word. */
	tmp &= BITMAP_FIRST_WORD_MASK(start);
	start = ALIGN_DOWN(start, BITS_PER_LONG);
	while (!tmp) {
		start += BITS_PER_LONG;
		if (start >= end)
			return end;

		tmp = addr[start / BITS_PER_LONG] ^ invert;
	}
	return MIN(start + find_first_bit(tmp), end);
}

/* unity 32K = 0x8000
 * size = 1G = 0x40000000
 * count = 0x40000000/0x8000 = 0x8000 = 32K
 */
s32 bitmap_create(struct bitmap *sbitmap, u32 size, u32 order)
{
	u32 *map = NULL;
	u32 bits = size >> order;

	/* this can prevent overstep the memory boundary */
	map = TEE_Malloc(ALIGN(bits, BITS_PER_LONG) / BITS_PER_CHAR, 0);
	if (!map) {
		tloge("%s:count = %x, unity = %x, len = %x\n", __func__, bits, order, ALIGN(bits, BITS_PER_LONG) / BITS_PER_CHAR);
		return -1;
	}

	/* just for the first bit is always equal 1 */
	(void)memset_s(map, ALIGN(bits, BITS_PER_LONG) / BITS_PER_CHAR, 0x0,
		ALIGN(bits, BITS_PER_LONG) / BITS_PER_CHAR);
	sbitmap->map = map;

	sbitmap->bits = bits;
	sbitmap->order = order;

	tlogd("%s: success bits = %x, order = %x\n", __func__, bits, order);

	return 0;
}

void bitmap_destroy(struct bitmap *sbitmap)
{
	TEE_Free(sbitmap->map);
}

s32 bitmap_find_next_zero_area(struct bitmap *sbitmap, u32 size)
{
	u32 index, i;
	u32 start_ibit = 0;
	u32 end_ibit, nbits;
	u32 max_bits = sbitmap->bits;
	u32 order = sbitmap->order;
	u32 *map = sbitmap->map;

	nbits = size >> order;
again:
	/* find the first zera bit */
	index = find_next_bit(map, max_bits, start_ibit, (u32)~0UL);
	if (index >= max_bits)
		return -1;

	end_ibit = index + nbits;
	if (end_ibit > max_bits)
		return -1;

	/* check the next nbit is zero area */
	i = find_next_bit(map, end_ibit, index, 0UL);
	if (i < end_ibit) {
		start_ibit = i + 1;
		goto again;
	}
	tlogd("index = 0x%x, start_ibit = 0x%x, nbits= 0x%x, size = 0x%x\n",
		index, start_ibit, nbits, size);

	return index;
}

void bitmap_set_ll(struct bitmap *sbitmap, u32 start_ibits, u32 size)
{
	u32 *map = sbitmap->map;
	u32 order = sbitmap->order;
	u32 nbits = (ALIGN(size, 1 << order)) >> order;
	u32 end_ibits = start_ibits + nbits;
	u32 sword = start_ibits / BITS_PER_LONG;
	u32 nr_bits = start_ibits % BITS_PER_LONG, nr_words;
	u32 value = 0;

	/* start bits and end bits at same word */
	if ((end_ibits / BITS_PER_LONG) == (start_ibits / BITS_PER_LONG)) {
		value = (~0UL << (start_ibits % BITS_PER_LONG) &
			 ~0UL >> (BITS_PER_LONG - end_ibits % BITS_PER_LONG));
		map[sword] |= value;
		return;
	}
	/* set the First Word */
	if (nr_bits) {
		map[sword++] |= ~0UL << nr_bits;
		nbits -= (BITS_PER_LONG - nr_bits);
	}

	/* set the Mid Words */
	nr_words = nbits / BITS_PER_LONG;
	nr_bits = nbits % BITS_PER_LONG;
	if (nr_words) {
		(void)memset_s(&map[sword], nr_words * sizeof(u32), (u32)~0UL,
			nr_words * sizeof(u32));
		sword += nr_words;
	}

	/* set the Last Word */
	if (nr_bits)
		map[sword] |= ~0UL >> (BITS_PER_LONG - nr_bits);
}

void bitmap_clear_ll(struct bitmap *sbitmap, u32 start_ibits, u32 size)
{
	u32 *map = sbitmap->map;
	u32 order = sbitmap->order;
	u32 nbits = (ALIGN(size, 1 << order)) >> order;
	u32 end_ibits = start_ibits + nbits;
	u32 sword = start_ibits / BITS_PER_LONG;
	u32 nr_bits = start_ibits % BITS_PER_LONG, nr_words;
	u32 value = 0;

	/* start bits and end bits at same word */
	if ((end_ibits / BITS_PER_LONG) == (start_ibits / BITS_PER_LONG)) {
		value = ~(~0UL << (start_ibits % BITS_PER_LONG) &
			  ~0UL >> (BITS_PER_LONG - end_ibits % BITS_PER_LONG));
		map[sword] &= value;
		return;
	}

	/* set the First Word */
	if (nr_bits) {
		map[sword++] &= ~(~0UL << nr_bits);
		nbits -= (BITS_PER_LONG - nr_bits);
	}

	/* set the Mid Words */
	nr_words = nbits / BITS_PER_LONG;
	nr_bits = nbits % BITS_PER_LONG;
	if (nr_words) {
		(void)memset_s(&map[sword], nr_words * sizeof(u32), 0UL,
			nr_words * sizeof(u32));
		sword += nr_words;
	}

	/* set the Last Word */
	if (nr_bits)
		map[sword] &= ~(~0UL >> (BITS_PER_LONG - nr_bits));
}

u32 bitmap_count_ll(struct bitmap *sbitmap)
{
	return sbitmap->bits;
}

bool bitmap_empty(struct bitmap *sbitmap)
{
	u32 count   = sbitmap->bits / BITS_PER_LONG;
	u32 *addr = sbitmap->map;
	u32 index = 0;

	for (index = 0; index < count; index++) {
		if (addr[index] != 0)
			return FALSE;
	}
	return TRUE;
}
