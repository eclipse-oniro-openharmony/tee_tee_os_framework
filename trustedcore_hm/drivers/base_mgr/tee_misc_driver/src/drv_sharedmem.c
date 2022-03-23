/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: shared mem API
 * Create: 2022-01-13
 */
#include "drv_sharedmem.h"
#include <securec.h>
#include "tee_log.h"
#include "plat_cfg.h"
#include "sre_syscalls_id.h"
#include "sys/mman.h"
#include "shared_mem_api.h"
#ifndef CONFIG_MISC_DRIVER
#include <hm_mman_ext.h>
#include "drv_thread.h"
#include <hmdrv_stub.h>
#endif
#include "drv_module.h"
#include "drv_param_type.h"
#include <plat_features.h>
#include "boot_sharedmem.h"

static uintptr_t g_sharedmem_vaddr = 0;
static uint32_t g_sharedmem_size = 0;
static bool g_sharedmem_flag = false;

static TEE_UUID g_allperm_uuid = { 0xffffffff, 0xffff, 0xffff, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }};

int32_t sharedmem_addr_init(void)
{
    int32_t ret;
    uint32_t size = SHAREDMEM_DEFAULT_SIZE;
retry:
    g_sharedmem_vaddr = (uintptr_t)malloc(size);
    if (g_sharedmem_vaddr == 0) {
        tloge("malloc sharedmem buffer failed\n");
        return -1;
    }

    ret = get_sharedmem_from_kernel((void *)g_sharedmem_vaddr, (void *)&size);
    if (ret != 0) {
        if (size > SHAREDMEM_DEFAULT_SIZE) {
            tloge("sharedmem size is not enough, need to realloc\n");
            free((void *)g_sharedmem_vaddr);
            goto retry;
        }
        free((void *)g_sharedmem_vaddr);
        g_sharedmem_vaddr = 0;

        /* no sharedmem */
        if (size == 0)
            return 0;
        tloge("get sharedmem form kernel failed\n");
        return -1;
    }
    g_sharedmem_size = size;
    tlogd("get sharedmem from kernel success, size=0x%x\n", size);
    g_sharedmem_flag = true;
    return 0;
}

static uint32_t share_mem_value_check(const struct tlv_item_tag *item)
{
    uint32_t len = item->length;
    uint32_t uuid_len = item->uuid_len;

    if (item->magic == (MAIGC_WORD + len + uuid_len)) {
        return 0;
    } else {
        tloge("magic check failed, item->magic is 0x%x len is 0x%x uuid_len is 0x%x\n",
              item->magic, len, uuid_len);
        return 1;
    }
}

int32_t get_sharedmem_addr(uintptr_t *sharedmem_vaddr, bool *sharedmem_flag, uint32_t *sharedmem_size)
{
    if (sharedmem_vaddr == NULL || sharedmem_flag == NULL || sharedmem_size == NULL) {
        tloge("bad paras\n");
        return -1;
    }

    *sharedmem_vaddr = g_sharedmem_vaddr;
    *sharedmem_flag = g_sharedmem_flag;
    *sharedmem_size = g_sharedmem_size;

    return 0;
}

static struct tlv_item_tag *share_mem_tlv_find(const struct tlv_tag *tlv, const char *type, const uint32_t type_size)
{
    struct tlv_item_tag *pos = NULL;
    uint32_t len = 0;
    uintptr_t sharedmem_vaddr = g_sharedmem_vaddr + sizeof(struct tlv_tag);

    if (tlv == NULL)
        return NULL;
    pos = (struct tlv_item_tag *)sharedmem_vaddr;
    for (uint32_t i = 0; i < tlv->tlv_num; i++) {
        uint32_t ret = share_mem_value_check(pos);
        if (ret != 0)
            return NULL;

        len += pos->length + pos->uuid_len + sizeof(struct tlv_item_tag);

        if (len > tlv->total_len) {
            tloge("the length is large then the total len\n");
            return NULL;
        }

        if (memcmp(pos->type, type, type_size) == 0 && strnlen(pos->type, TYPE_LEN) <= type_size)
            return pos;
        if (i < tlv->tlv_num - 1)
            pos = (struct tlv_item_tag *)(sharedmem_vaddr + len);
    }

    tloge("The type value is null\n");
    return NULL;
}

#ifndef CONFIG_MISC_DRIVER
uint32_t get_caller_uuid(spawn_uuid_t *uuid)
{
    tid_t tid;
    int32_t pid;
    int32_t pid_call = INVALID_CALLER_PID;

    if (uuid == NULL)
        return -EINVAL;

    int32_t ret = hm_gettid(&tid);
    if (ret != 0) {
        hm_error("failed to get tid\n");
        return -ESRCH;
    }

    /* for invalid pid, return "No such process" */
    ret = get_callerpid_by_tid(tid, (pid_t *)&pid_call);
    if (ret != 0)
        return -ESRCH;

    pid = (int)((uint32_t)pid_call & LOW_MASK_16BIT);

    if (hm_getuuid(pid, uuid) != 0) {
        tloge("get uuid error, pid:%d\n", pid);
        return 1;
    }

    return 0;
}
#endif

static uint32_t share_mem_uuid_check(const void *uuid_buffer, uint32_t length)
{
    spawn_uuid_t spawn_uuid = { 0 };
    if (uuid_buffer == NULL)
        return 1;
    if (length % sizeof(TEE_UUID) != 0)
        return 1;

#ifndef CONFIG_MISC_DRIVER
    if (get_caller_uuid(&spawn_uuid) != 0) {
        tloge("get uuid error");
        return 1;
    }
#else
    get_current_caller_uuid(&(spawn_uuid.uuid));
#endif

    TEE_UUID *uuid = (TEE_UUID *)uuid_buffer;

    if (memcmp(uuid, &g_allperm_uuid, sizeof(TEE_UUID)) == 0)
        return 0;

    for (uint32_t i = 0; i < length / sizeof(TEE_UUID); i++) {
        if (memcmp(uuid, &(spawn_uuid.uuid), sizeof(TEE_UUID)) == 0)
            return 0;
        uuid++;
    }

    return 1;
}

static uint32_t check_tlv_paras(struct tlv_paras tlv_paras)
{
    if (!g_sharedmem_flag || g_sharedmem_vaddr == 0) {
        tloge("no shared mem at this platform or sharedmem init failed\n");
        return 1;
    }

    if (tlv_paras.buffer == NULL || tlv_paras.type == NULL) {
        tloge("invalid param\n");
        return 1;
    }

    if (tlv_paras.type_size == 0 || tlv_paras.type_size > TYPE_LEN) {
        tloge("invalid type_size param\n");
        return 1;
    }

    return 0;
}

static int32_t get_tlv_msg(struct tlv_paras tlv_paras, uint32_t *size, bool uuid_check, bool clear_flag)
{
    errno_t rc;
    uint32_t ret;

    if (check_tlv_paras(tlv_paras) != 0)
        return 1;

    struct tlv_tag *tlv = (struct tlv_tag *)g_sharedmem_vaddr;
    if (tlv->magic != MAIGC_WORD) {
        tloge("magic is error magic is 0x%x\n", tlv->magic);
        return 1;
    }

    if (tlv->total_len + sizeof(struct tlv_tag) > g_sharedmem_size) {
        tloge("the tlv total len is too large, length is 0x%x\n", tlv->total_len);
        return 1;
    }

    struct tlv_item_tag *item = share_mem_tlv_find(tlv, tlv_paras.type, tlv_paras.type_size);
    if (item == NULL)
        return 1;

    uint32_t len = item->length;
    uint32_t uuid_len = item->uuid_len;
    void *value = tlv_item_data(item);

    if (uuid_check == true) {
        ret = share_mem_uuid_check(value, uuid_len);
        if (ret != 0)
            return 1;
    }

    if (len > *size) {
        tloge("buffer length should big than put in value 0x%x\n", len);
        return 1;
    }

    rc = memcpy_s(tlv_paras.buffer, *size, value + uuid_len, len);
    if (rc != EOK) {
        tloge("copy sharedmem failed type is %s\n", tlv_paras.type);
        return 1;
    }

    *size = len;

    if (clear_flag) {
        rc = memset_s(value + uuid_len, len, 0, len);
        if (rc != EOK) {
            tloge("clear tlv buffer failed\n");
            return 1;
        }
    }

    return 0;
}

int32_t get_tlv_shared_mem(const char *type, uint32_t type_size, void *buffer, uint32_t *size, bool clear_flag)
{
    int32_t ret;
    if (type == NULL || buffer == NULL || size == NULL)
        return -1;
    struct tlv_paras tlv_paras = { type, type_size, buffer, 0};
    ret = get_tlv_msg(tlv_paras, size, true, clear_flag);
    if (ret != 0) {
        tloge("get sharedmem error 0x%x\n", ret);
        return ret;
    }
    return 0;
}

int32_t get_tlv_shared_mem_drv(const char *type, uint32_t type_size, void *buffer, uint32_t *size, bool clear_flag)
{
    int32_t ret;

    if (type == NULL || buffer == NULL || size == NULL)
        return -1;

    struct tlv_paras tlv_paras = { type, type_size, buffer, 0 };

    ret = get_tlv_msg(tlv_paras, size, false, clear_flag);
    if (ret != 0) {
        tloge("get sharedmem drv error 0x%x\n", ret);
        return ret;
    }

    return 0;
}

uint32_t get_sharedmem_vaddr()
{
    return g_sharedmem_vaddr;
}

bool get_sharedmem_flag()
{
    return g_sharedmem_flag;
}
