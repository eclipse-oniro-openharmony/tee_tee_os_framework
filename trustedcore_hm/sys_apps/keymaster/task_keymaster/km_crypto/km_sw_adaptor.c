/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster key transfer between keymaster and software engine
 * Create: 2020-11-09
 */

#ifdef BORINGSSL_ENABLE
#include "openssl/nid.h"
#else
#include "openssl/obj_mac.h"
#endif
#include "keymaster_defs.h"
#include "km_crypto_adaptor.h"
static keymaster_uint2uint g_km_sw_hash[] = {
    { KM_DIGEST_MD5,       NID_md5},
    { KM_DIGEST_SHA1,      NID_sha1},
    { KM_DIGEST_SHA_2_224, NID_sha224},
    { KM_DIGEST_SHA_2_256, NID_sha256},
    { KM_DIGEST_SHA_2_384, NID_sha384},
    { KM_DIGEST_SHA_2_512, NID_sha512}
};

int32_t km_hash_to_soft_hash(keymaster_digest_t digest, uint32_t *hash_function)
{
    if (hash_function == NULL) {
        tloge("the hash_function is null\n");
        return -1;
    }
    if (digest == KM_DIGEST_NONE)
        return 0;
    if (look_up_table(g_km_sw_hash, sizeof(g_km_sw_hash) / sizeof(keymaster_uint2uint), digest, hash_function) !=
        TEE_SUCCESS) {
        tloge("unsupported digest mode %u\n", digest);
        return -1;
    }
    return 0;
}