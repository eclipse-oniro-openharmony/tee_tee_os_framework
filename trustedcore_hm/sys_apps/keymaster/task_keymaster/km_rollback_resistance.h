/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: keymaster rollback resistance header
 * Create: 2017-01-17
 */
#ifndef __KM_ROLLBACK_H
#define __KM_ROLLBACK_H
#if (defined(TEE_SUPPORT_RPMB_64BIT) || defined(TEE_SUPPORT_RPMB_32BIT))
#include "tee_internal_api.h"
#include "keyblob.h"
#include "tee_mem_mgmt_api.h"
#define FILE_NAME_LEN    64
#define DOUBLE_SIZE      2
#define RESERVE_SIZE     8
/* Every metafile's size is designed as 4K. header:8bytes; nodes:4088bytes;Max_count:4088/(32+1+3+8)=92. */
#define MAX_NODE_COUNT   92
typedef enum {
    TYPE_CTL_NONE,
    TYPE_CTL_EIMA_POLICY,
    TYPE_CTL_RESERVED
} kb_ctl_type;

typedef enum {
    KB_ENABLE,  /* Keyblob could be used */
    KB_DISABLE, /* keyblob forbidden to be used. But keep its metadata in RPMB. */
    KB_DELETE   /* Delete keyblob's metadata, and forbid using it. */
} kb_eima_policy;

typedef struct {
    bool enabled;
    uint8_t ctl_type;     /* TYPE_CTL_EIMA_POLICY */
    uint8_t p_compromised; /* policy for EIMA compromised state(kb_eima_policy) */
} ctl_eima_policy_t;

typedef struct kmd_node {
    uint8_t hmac[HMAC_SIZE]; /* metadata content, now is HMAC value. */
    uint8_t version;
    ctl_eima_policy_t eima_policy;
    uint8_t reserved[RESERVE_SIZE];
} meta_element_t;

typedef struct kmds_header {
    uint32_t count;                   /* km node count,  the maximum number of the node object could be allocated. */
    uint32_t count_used;              /* km node used count, the real allocated node object number. */
    meta_element_t n[MAX_NODE_COUNT]; /* nodes array */
} meta_file_t;

int kb_metafile_find(const uint8_t *kb_hmac, uint32_t kb_hmac_len);
int kb_metafile_write(const uint8_t *kb_hmac, uint32_t kb_hmac_len);
int32_t kb_metafile_delete(const uint8_t *kb_hmac, uint32_t kb_hmac_len);
int kb_metafile_update(const uint8_t *old_kb_hmac, const uint8_t *new_kb_hmac, uint32_t kb_hmac_len);

TEE_Result keyblob_integrity_check(keyblob_head *keyblob, uint32_t keyblob_size);
TEE_Result kb_metafile_load(const uint8_t *kb_hmac, uint32_t kb_hmac_len, char *file_located,
                            uint32_t file_name_len, meta_file_t *outbuff);
TEE_Result kmds_set_keypolicy(uint8_t *kmds_data, uint8_t *hmac, const ctl_eima_policy_t *key_policy);
void check_rpmb_write(TEE_Result ret);
#endif
#endif
