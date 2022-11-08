/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "handle_ca_hashfile_verify.h"
#include <sys/mman.h>
#include <mem_ops_ext.h> /* tee_map_sharemem */
#include <string.h>
#include "tee_crypto_api.h"
#include "tee_crypto_hal.h"
#include "tee_log.h"
#include "ca_hashfile_config.h"
#include "tee_crypto_signature_verify.h"
#include "auth/tee_auth_sign_rsa.h"

#define SHA256_HASH_LEN    32
#define RESERVE_LEN 2
struct ca_hash_file_s {
    uint32_t total_len;
    uint32_t file_ver;
    uint32_t magic;
    uint32_t xml_type;
    uint32_t reserve[RESERVE_LEN];
    uint32_t sign_offset;
    uint32_t sign_length;
    uint32_t ca_num;
    uint8_t data[1];
};

static RSA *get_rsa_pub_key(void)
{
    const rsa_pub_key_t *cahash_pub_key = get_cahash_rsa_pub_key();
    if (cahash_pub_key == NULL)
        return NULL;

    return rsa_build_public_key(cahash_pub_key);
}

static TEE_Result calc_hash256(const uint8_t *src_data, uint32_t src_len, uint8_t *dest_data, size_t dest_len)
{
    if (src_data == NULL || dest_data == NULL || dest_len != SHA256_HASH_LEN) {
        tloge("src data or dest data is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_OperationHandle crypto_ops = NULL;
    TEE_Result ret = TEE_AllocateOperation(&crypto_ops, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (ret != TEE_SUCCESS) {
        tloge("allocate operation fail 0x%x\n", ret);
        return ret;
    }
    ret = TEE_SetCryptoFlag(crypto_ops, SOFT_CRYPTO);
    if (ret != TEE_SUCCESS) {
        tloge("set soft engine failed ret=0x%x\n", ret);
        goto free_operation;
    }
    ret = TEE_DigestDoFinal(crypto_ops, src_data, src_len, dest_data, &dest_len);
    if (ret != TEE_SUCCESS) {
        tloge("digest do final fail ret=0x%x, srclen=0x%x, dst_len=0x%x\n", ret, src_len, dest_len);
        goto free_operation;
    }

free_operation:
    TEE_FreeOperation(crypto_ops);
    return ret;
}

/* check ca hash file */
static TEE_Result check_hash_file_params(const struct ca_hash_file_s *hash_file, uint32_t size)
{
    uint32_t hash_file_maxsize = get_hashfile_max_size();

    if (size < sizeof(*hash_file)) {
        tloge("hash file size is invalid, %u\n", size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (hash_file->total_len > hash_file_maxsize || hash_file->total_len != size) {
        tloge("hash file total len is invaild, %u\n", hash_file->total_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (hash_file->sign_offset > hash_file->total_len) {
        tloge("hash file sign offset is invaild, %u, %u\n", hash_file->sign_offset, hash_file->total_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((hash_file->sign_offset + hash_file->sign_length) != hash_file->total_len) {
        tloge("hash file invaild: total len:0x%x, sign offset:0x%x, sign length:0x%x\n",
            hash_file->total_len, hash_file->sign_offset, hash_file->sign_length);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result ca_hashfile_verify_signature(const uint8_t *buf, uint32_t size)
{
    struct ca_hash_file_s *hash_file = (struct ca_hash_file_s *)buf;

    TEE_Result ret = check_hash_file_params(hash_file, size);
    if (ret != TEE_SUCCESS) {
        tloge("hash file is invaild\n");
        return ret;
    }

    uint8_t verify_hash[SHA256_HASH_LEN] = {0};
    ret = calc_hash256(buf, hash_file->sign_offset, verify_hash, sizeof(verify_hash));
    if (ret != TEE_SUCCESS) {
        tloge("calc hash file fail, ret %x\n", ret);
        return ret;
    }

    ret = tee_secure_img_release_verify(verify_hash, sizeof(verify_hash), buf + hash_file->sign_offset,
        hash_file->sign_length, get_rsa_pub_key());
    if (ret != TEE_SUCCESS) {
        tloge("hash file verify failed, 0x%x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

TEE_Result perm_serv_ca_hashfile_verify(perm_srv_reply_msg_t *rsp, const perm_srv_req_msg_t *msg, uint32_t sender)
{
    TEE_Result ret;

    if (rsp == NULL || msg == NULL) {
        tloge("rsp or msg is NULL\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (sender != GLOBAL_HANDLE) {
        /* only gtask can call this interface */
        tloge("sender 0x%x no perm\n", sender);
        ret = TEE_ERROR_ACCESS_DENIED;
        goto out;
    }

    uint64_t map_addr;
    ret = tee_map_sharemem(sender, msg->req_msg.ca_hashfile_verify.buffer, msg->req_msg.ca_hashfile_verify.size,
        &map_addr);
    if (ret != TEE_SUCCESS) {
        tloge("map from task 0(gtask) failed, ret 0x%x\n", ret);
        goto out;
    }

    /* verify ca hashfile */
    ret = ca_hashfile_verify_signature((uint8_t *)(uintptr_t)map_addr, msg->req_msg.ca_hashfile_verify.size);
    if (ret != 0)
        tloge("ca hashfile verify failed, ret 0x%x\n", ret);

    if (map_addr != 0) {
        if (munmap((void *)(uintptr_t)map_addr, msg->req_msg.ca_hashfile_verify.size) != 0) {
            tloge("perm unmap error\n");
            ret = TEE_ERROR_GENERIC;
        }
    }

out:
    rsp->reply.ret = ret;
    return ret;
}
