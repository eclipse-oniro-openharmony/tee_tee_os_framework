/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: shared mem API
 * Create: 2022-01
 */
#ifndef DRIVERS_SHAREDMEM_H
#define DRIVERS_SHAREDMEM_H
#include <types.h>
#include "tee_defines.h"
#define MAP_INVALID_32BITADDR        0xFFFFFFFF
#define MAP_INVALID_64BITADDR        0xFFFFFFFFFFFFFFFF
#define SRE_MAX_NOMAP_MAP_COUNT      19
#define SHAREDMEM_DEFAULT_SIZE       0x1000
#define TOKEN_BUF_SIZE               0x1000
#define MAIGC_WORD 0xfd544c56
#define LOW_MASK_16BIT 0xffff
#define TYPE_LEN 32

struct tlv_item_tag {
    char type[TYPE_LEN];
    uint32_t uuid_len;
    uint32_t length;
    uint32_t magic;
}__attribute__((__packed__));

struct tlv_tag {
    uint32_t magic;
    uint32_t tlv_num;
    uint32_t total_len;
}__attribute__((__packed__));

struct tlv_paras {
    const char *type;
    uint32_t type_size;
    void *buffer;
    uint32_t size;
}__attribute__((__packed__));

struct msg_paras {
    struct tlv_paras tlv_msg;
    bool clear_flag;
    uint32_t shared_token;
}__attribute__((__packed__));

#define tlv_item_data(item) ((void *)((char *)(item) + sizeof(struct tlv_item_tag)))
int32_t get_tlv_shared_mem(const char *type, uint32_t type_size, void *buffer, uint32_t *size, bool clear_flag);
int32_t get_tlv_shared_mem_drv(const char *type, uint32_t type_size, void *buffer, uint32_t *size, bool clear_flag);
int32_t sharedmem_addr_init(void);
uint32_t get_sharedmem_vaddr();
bool get_sharedmem_flag();
#ifdef CONFIG_MISC_DRIVER
void get_current_caller_uuid(TEE_UUID *uuid);
#endif

#endif
