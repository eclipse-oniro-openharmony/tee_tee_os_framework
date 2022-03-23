#include "sec_adapt.h"
#include "sre_log.h"
#include "hi_sec_api.h"
#include "securec.h"

uint32_t hi_sec_derive_key(uint8_t *salt, uint32_t salt_len, uint8_t *key_out)
{
	errno_t ret_s;
	int32_t ret;

    struct hi_sec_kdf_internal para = {0};
    para.iter = HI_KDF_ITER_COUNT;

    ret_s = memcpy_s(para.key, HI_KDF_PASSWD_LEN, salt, salt_len);
    if (ret_s != EOK) {
        tloge("Failed to copy the salt to sec\n");
        return -1;
    }

    ret = hi_kdf_to_store(&para);
	if (ret != 0) {
		tloge("Failed to derive key from sec\n");
		return -1;
	}

    ret_s = memcpy_s(key_out, HI_KDF_DK_LEN, para.dk, HI_KDF_DK_LEN);
	if (ret_s != EOK) {
		tloge("Failed to copy the key\n");
		return -1;
	}

	return 0;
}

uint32_t hi_sec_gen_trng(uint8_t *rnd_out, uint32_t rnd_len)
{
    errno_t ret_s;
    int32_t ret;
    uint32_t times = 0;
    uint32_t i;
    struct hi_sec_trng trng_param = {0};

    if (rnd_out == NULL || rnd_len == 0) {
        tloge("invalid rnd_out or rnd_len\n");
        return -1;
    }

    times = rnd_len / HI_RNG_DATALEN;
    for(i = 0; i < times; i++) {
        ret = hi_sec_trng_get(&trng_param);
        if (ret != 0) {
            tloge("Failed to get random num from sec\n");
            return -1;
        }

        ret_s = memcpy_s(rnd_out + i * HI_RNG_DATALEN, rnd_len - i * HI_RNG_DATALEN,
                         trng_param.rng, HI_RNG_DATALEN);
        if (ret != EOK) {
            tloge("Failed to copy the random num\n");
            return -1;
        }
    }

    uint32_t last_len = rnd_len % HI_RNG_DATALEN;
    if (last_len != 0) {
        ret = hi_sec_trng_get(&trng_param);
        if (ret != 0) {
            tloge("Failed to get random num from sec\n");
            return -1;
        }

        ret_s = memcpy_s(rnd_out + times * HI_RNG_DATALEN, rnd_len - times * HI_RNG_DATALEN,
                         trng_param.rng, last_len);
        if (ret != EOK) {
            tloge("Failed to copy the random num\n");
            return -1;
        }
    }

    return 0;
}
