#ifndef PLATDRV_SEC_ADAPT_H
#define PLATDRV_SEC_ADAPT_H

#include <stdint.h>

uint32_t hi_sec_derive_key(uint8_t *salt, uint32_t salt_len, uint8_t *key_out);
uint32_t hi_sec_gen_trng(uint8_t *rnd_out, uint32_t rnd_len);

#endif
