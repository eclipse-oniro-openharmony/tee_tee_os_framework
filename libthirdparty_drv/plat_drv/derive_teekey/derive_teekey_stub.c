#include "derive_teekey.h"

uint32_t plat_derive_teekey(uint8_t *key, uint32_t size)
{
	uint32_t i;

	if (!key) {
		tloge("error, key is NULL\n");
		return 1;
	}

	if (size != PLAT_TEEKEY_SIZE) {
		tloge("error, size 0x%x is illegal\n", size);
		return 1;
	}

	tloge("derive teekey is stub func, will derive all zero key\n");

	for (i = 0; i < size; i++)
		key[i] = 0;

	return 0;
}
