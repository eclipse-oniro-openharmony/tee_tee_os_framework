/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: huk manager task.
 * Author: PengShuai pengshuai@huawei.com
 * Create: 2020-05-22
 */
#include <securec.h>
#include <sys/mman.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <mem_ops_ext.h>
#include <tee_defines.h>
#include <ac.h>
#include <ac_dynamic.h>
#include <api/errno.h>
#include <sys/usrsyscall.h>
#include <sre_syscalls_ext.h>
#include <ipclib.h>
#include <tamgr_ext.h>
#include <procmgr_ext.h>
#include <tee_private_api.h>
#include <tee_crypto_hal.h>
#include <ta_framework.h>
#include <crypto_hal_hmac.h>
#include <crypto_hal_derive_key.h>
#include <chip_info.h>
#include <oemkey.h>
#include <crypto_wrapper.h>
#include <tee_ext_api.h>
#include <tee_config.h>
#include <tee_ss_agent_api.h>
#include "huk_service_msg.h"
#include "huk_service_config.h"

#define HUK_SRV_SUCCESS             0
#define HUK_SRV_ERROR               (-1)
#define MAGIC_STR_LEN               20

#define WEAK __attribute__((weak))

#define BSS_START_MAGIC 0x12345678
#define BSS_END_MAGIX   0x87654321

#define TEE_DEVICE_ID_LEN sizeof(TEE_UUID)

/* size of HMAC output bytes */
#define SIZE_HMAC256_OBYTES 32
#define SIZE_HMAC384_OBYTES 48
#define SIZE_HMAC512_OBYTES 64

/* expand key usage, 10x for derive, 20x for crypto */
enum EXPAND_KEY_USAGE {
    EKU_FOR_DERIVE_ECC = 101,
    EKU_FOR_CRYPTO_AES = 201
};

/* KDS TA Level, bigger level means higher secure level? */
enum PLATKEY_CALLER_LEVEL {
    LEVEL_COM = 0,  /* for TAs which is not KDS TA , common TA */
    LEVEL_UND = 20, /* for KDS TA - Caller TA not defined in level */
    LEVEL_KCA = 21, /* for KDS CA2TA, caller is CA */
    LEVEL_3ST = 23, /* for KDS TA */
    LEVEL_6ST = 26, /* for KDS TA */
    LEVEL_9ST = 29, /* for KDS TA */
    LEVEL_ERR = 255
};

/* offset of the salt_ta, if sizeof(UUID) changes, we need change this */
#define SIZE_UUID       16
/* salt_ta [2-47] is reserved, now filed with 0x00 */
#define KS_OFTS_USAGE      0   /* for EXPAND_KEY_USAGE  */
#define KS_OFTS_KDS_CALLER 1   /* for PLATKEY CALLER LEVEL */
#define KS_OFTS_TA_UUID    48  /* [48 - 63]  UUID       */
#define KS_OFTS_EXINFO     64  /* [64 - 127] EXTRA INFO */
#define KS_OFTS_TOTAL      128 /* total size of salt    */

typedef TEE_Result (*cmd_func)(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
                               uint32_t self_pid, uint32_t sndr_pid, const TEE_UUID *uuid);

struct cmd_operate_config_s {
    uint32_t cmd_id;
    cmd_func operate_func;
};

uint32_t WEAK g_ta_bss_start = BSS_START_MAGIC;
uint32_t WEAK g_ta_bss_end = BSS_END_MAGIX;
static void huk_clear_ta_bss(void)
{
#ifndef CONFIG_DYNLINK
    uint32_t ta_bss_start = (uint32_t)&g_ta_bss_start;
    uint32_t ta_bss_end = (uint32_t)&g_ta_bss_end;

    if (g_ta_bss_start == BSS_START_MAGIC && g_ta_bss_end == BSS_END_MAGIX) {
        tlogd("only weak bss define\n");
        return;
    }

    if (ta_bss_end > ta_bss_start) {
        int32_t sret = memset_s((void *)ta_bss_start, ta_bss_end - ta_bss_start,
                                0, ta_bss_end - ta_bss_start);
        if (sret != EOK)
            tloge("elf _s fail. line = %d, sret = %d\n", __LINE__, sret);
    } else if (ta_bss_end == ta_bss_start) {
        tlogd("bss size is zero \n");
    } else {
        tloge("ta bss address is error\n");
    }
#endif
}

static cref_t huk_get_mymsghdl(void)
{
    struct hmapi_thread_local_storage *tls = NULL;

    tls = hmapi_tls_get();
    if (tls == NULL)
        return CREF_NULL;

    if (tls->msghdl == 0) {
        cref_t msghdl;
        msghdl = hm_msg_create_hdl();
        if (is_ref_err(msghdl))
            return CREF_NULL;

        tls->msghdl = msghdl;
    }

    return tls->msghdl;
}

static int32_t huk_srv_map_from_task(uint32_t in_task_id, uint64_t va_addr, uint32_t size,
                                     uint32_t out_task_id, uint64_t *virt_addr)
{
    (void)out_task_id;
    uint64_t vaddr;
    int32_t ret;

    ret = tee_map_sharemem(in_task_id, va_addr, size, &vaddr);
    if (ret == 0)
        *virt_addr = (uintptr_t)vaddr;
    else
        tloge("huk map from %u failed\n", in_task_id);

    return ret;
}

static void huk_srv_task_unmap(uint64_t virt_addr, uint32_t size)
{
    if (virt_addr == 0)
        return;
    if (munmap((void *)(uintptr_t)virt_addr, size) != 0)
        tloge("huk srv unmap error\n");
}

static TEE_Result huk_task_takey_msg_check(const struct huk_srv_msg *msg)
{
    if ((msg == NULL) || (msg->data.takey_msg.salt_buf == 0) ||
        (msg->data.takey_msg.salt_size == 0) ||
        (msg->data.takey_msg.salt_size > CMAC_DERV_MAX_DATA_IN_SIZE)) {
        tloge("huk derive takey check salt messages failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((msg->data.takey_msg.key_buf == 0) ||
        (msg->data.takey_msg.key_size == 0) ||
        (msg->data.takey_msg.key_size > CMAC_DERV_MAX_DATA_IN_SIZE)) {
        tloge("huk derive takey check key messages failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result do_derive_takey(const uint8_t *salt_tmp, uint32_t salt_size, uint8_t *key_tmp, uint32_t key_size,
    uint32_t inner_iter_num)
{
    uint32_t derive_type = CRYPTO_KEYTYPE_HUK;

    struct memref_t salt = {0};
    salt.buffer = (uintptr_t)salt_tmp;
    salt.size = salt_size;

    struct memref_t cmac = {0};
    cmac.buffer = (uintptr_t)key_tmp;
    cmac.size = key_size;

    return tee_crypto_derive_root_key(derive_type, &salt, &cmac, inner_iter_num);
}

static TEE_Result huk_derive_takey_oldplat(uint64_t vmaddr_salt_shared, uint32_t salt_size,
                                           uint64_t vmaddr_key_shared, uint32_t key_size)
{
    errno_t rc;
    TEE_Result ret;
    uint8_t *salt_tmp = NULL;
    uint8_t *key_tmp = NULL;

    salt_tmp = TEE_Malloc(salt_size, 0);
    if (salt_tmp == NULL) {
        tloge("huk derive takey malloc salt memory failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    key_tmp = TEE_Malloc(key_size, 0);
    if (key_tmp == NULL) {
        tloge("huk derive takey malloc key memory failed\n");
        TEE_Free(salt_tmp);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    rc = memcpy_s(salt_tmp, salt_size, (uint8_t *)(uintptr_t)vmaddr_salt_shared, salt_size);
    if (rc != EOK) {
        TEE_Free(salt_tmp);
        salt_tmp = NULL;
        TEE_Free(key_tmp);
        return TEE_ERROR_SECURITY;
    }

    ret = do_derive_takey(salt_tmp, salt_size, key_tmp, key_size, 1);
    if (ret == TEE_SUCCESS) {
        if (memcpy_s((uint8_t *)(uintptr_t)vmaddr_key_shared, key_size, key_tmp, key_size) != EOK) {
            tloge("huk copy takey failed\n");
            ret = TEE_ERROR_SECURITY;
        }
    } else {
        tloge("huk cmac derive takey failed\n");
    }
    TEE_Free(salt_tmp);
    salt_tmp = NULL;
    (void)memset_s(key_tmp, key_size, 0, key_size);
    TEE_Free(key_tmp);
    return ret;
}

static TEE_Result huk_derive_takey_newplat(const TEE_UUID *uuid, uint64_t vmaddr_salt_shared, uint32_t salt_size,
                                           uint64_t vmaddr_key_shared, uint32_t key_size)
{
    errno_t rc;
    TEE_Result ret = TEE_ERROR_SECURITY;
    uint8_t *salt_tmp = NULL;
    uint8_t *key_tmp = NULL;

    salt_tmp = TEE_Malloc(salt_size + (uint32_t)sizeof(*uuid), 0);
    if (salt_tmp == NULL) {
        tloge("huk derive takey malloc memory of salt failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    key_tmp = TEE_Malloc(key_size, 0);
    if (key_tmp == NULL) {
        tloge("huk derive takey malloc memory of key failed\n");
        TEE_Free(salt_tmp);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    rc = memcpy_s(salt_tmp, salt_size, (uint8_t *)(uintptr_t)vmaddr_salt_shared, salt_size);
    if (rc != EOK)
        goto end_clean;

    rc = memcpy_s(salt_tmp + salt_size, sizeof(*uuid), uuid, sizeof(*uuid));
    if (rc != EOK)
        goto end_clean;

    ret = do_derive_takey(salt_tmp, salt_size + (uint32_t)sizeof(*uuid), key_tmp, key_size, 1);
    if (ret == TEE_SUCCESS) {
        if (memcpy_s((uint8_t *)(uintptr_t)vmaddr_key_shared, key_size, key_tmp, key_size) != EOK) {
            tloge("huk copy takey failed\n");
            ret = TEE_ERROR_SECURITY;
        }
    } else {
        tloge("huk cmac derive takey failed\n");
    }
end_clean:
    TEE_Free(salt_tmp);
    salt_tmp = NULL;
    (void)memset_s(key_tmp, key_size, 0, key_size);
    TEE_Free(key_tmp);
    return ret;
}

static TEE_Result huk_task_derive_takey(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
                                        uint32_t self_pid, uint32_t sndr_pid, const TEE_UUID *uuid)
{
    uint64_t vmaddr_salt_shared = 0;
    uint64_t vmaddr_takey_shared = 0;
    TEE_Result ret;
    bool is_compatible_plat = is_huk_service_compatible_plat();

    ret = huk_task_takey_msg_check(msg);
    if (ret != TEE_SUCCESS) {
        rsp->data.ret = ret;
        return ret;
    }
    if (huk_srv_map_from_task(sndr_pid, msg->data.takey_msg.key_buf,
                              msg->data.takey_msg.key_size, self_pid, &vmaddr_takey_shared) != 0) {
        tloge("huk service map takey buffer from 0x%x failed\n", sndr_pid);
        rsp->data.ret = TEE_ERROR_GENERIC;
        return rsp->data.ret;
    }
    if (huk_srv_map_from_task(sndr_pid, msg->data.takey_msg.salt_buf,
                              msg->data.takey_msg.salt_size, self_pid, &vmaddr_salt_shared) != 0) {
        tloge("huk service map salt buffer from 0x%x failed\n", sndr_pid);
        huk_srv_task_unmap(vmaddr_takey_shared, msg->data.takey_msg.key_size);
        rsp->data.ret = TEE_ERROR_GENERIC;
        return rsp->data.ret;
    }

    if (is_compatible_plat && (check_huk_access_permission(uuid) == TEE_SUCCESS)) {
        ret = huk_derive_takey_oldplat(vmaddr_salt_shared, msg->data.takey_msg.salt_size,
                                       vmaddr_takey_shared, msg->data.takey_msg.key_size);
    } else {
        ret = huk_derive_takey_newplat(uuid, vmaddr_salt_shared, msg->data.takey_msg.salt_size,
                                       vmaddr_takey_shared, msg->data.takey_msg.key_size);
    }

    huk_srv_task_unmap(vmaddr_salt_shared, msg->data.takey_msg.salt_size);
    huk_srv_task_unmap(vmaddr_takey_shared, msg->data.takey_msg.key_size);
    rsp->data.ret = ret;
    return ret;
}

#define KEY_DERIVE_BLOCK_SIZE 16
#define ITER_DERIVE_KEY2_SIZE (KEY_DERIVE_BLOCK_SIZE * 2)
static TEE_Result do_derive_takey2(const uint8_t *salt, uint32_t salt_size,
    uint8_t *key, uint32_t key_size, uint32_t inner_iter_num)
{
    errno_t rc;
    TEE_Result ret;
    uint8_t *tmp_sec = NULL;
    uint32_t tmp_size;

    tmp_size = salt_size + 1; /* add additional 1 byte to store count */
    tmp_sec  = TEE_Malloc(tmp_size, 0);
    if (tmp_sec == NULL) {
        tloge("alloc mem failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    rc = memcpy_s(tmp_sec, tmp_size, salt, salt_size);
    if (rc != EOK) {
        tloge("copy data failed, rc 0x%x\n", rc);
        TEE_Free(tmp_sec);
        return TEE_ERROR_SECURITY;
    }

    for (uint32_t i = 0; i < key_size / KEY_DERIVE_BLOCK_SIZE; i++) {
        tmp_sec[salt_size] = (uint8_t)i;
        ret = do_derive_takey(tmp_sec, tmp_size, key + KEY_DERIVE_BLOCK_SIZE * i,
            KEY_DERIVE_BLOCK_SIZE, inner_iter_num);
        if (ret != TEE_SUCCESS) {
            tloge("derive key for num:%u failed, ret=0x%x\n", i, ret);
            TEE_Free(tmp_sec);
            return ret;
        }
    }

    TEE_Free(tmp_sec);
    return TEE_SUCCESS;
}

static TEE_Result do_derive_takey2_iter(const TEE_UUID *uuid, struct memref_t *salt_shard,
    struct memref_t *takey_shared, uint32_t outer_iter_num, uint32_t inner_iter_num)
{
    TEE_Result ret;
    uint32_t salt_tmp_size = salt_shard->size > ITER_DERIVE_KEY2_SIZE ? salt_shard->size : ITER_DERIVE_KEY2_SIZE;

    bool is_compatible = is_huk_service_compatible_plat() && check_huk_access_permission(uuid) == TEE_SUCCESS;
    if (!is_compatible)
        salt_tmp_size += (uint32_t)sizeof(*uuid);

    uint8_t *salt_tmp = TEE_Malloc(salt_tmp_size, 0);
    if (salt_tmp == NULL) {
        tloge("huk derive takey malloc salt memory failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    uint8_t *key_tmp = TEE_Malloc(takey_shared->size, 0);
    if (key_tmp == NULL) {
        tloge("huk derive takey malloc key memory failed\n");
        TEE_Free(salt_tmp);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    errno_t rc = memcpy_s(salt_tmp, salt_tmp_size, (uint8_t *)(uintptr_t)salt_shard->buffer, salt_shard->size);
    if (rc != EOK) {
        ret = TEE_ERROR_SECURITY;
        goto clean;
    }

    if (!is_compatible)
        (void)memcpy_s(salt_tmp + salt_shard->size, sizeof(*uuid), uuid, sizeof(*uuid));

    for (uint32_t i = 0; i < outer_iter_num; i++) {
        ret = do_derive_takey2(salt_tmp, salt_tmp_size, key_tmp, takey_shared->size, inner_iter_num);
        if (ret != TEE_SUCCESS)
            goto clean;

        rc = memcpy_s(salt_tmp, salt_tmp_size, key_tmp, ITER_DERIVE_KEY2_SIZE);
        if (rc != EOK) {
            ret = TEE_ERROR_SECURITY;
            goto clean;
        }
    }

    if (memcpy_s((uint8_t *)(uintptr_t)takey_shared->buffer, takey_shared->size, key_tmp, takey_shared->size) != EOK) {
        tloge("huk copy takey failed\n");
        ret = TEE_ERROR_SECURITY;
    }

clean:
    TEE_Free(salt_tmp);
    salt_tmp = NULL;
    (void)memset_s(key_tmp, takey_shared->size, 0, takey_shared->size);
    TEE_Free(key_tmp);
    return ret;
}

static TEE_Result huk_task_derive_takey2_iter(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
    uint32_t self_pid, uint32_t sndr_pid, const TEE_UUID *uuid)
{
    uint64_t vmaddr_salt_shared = 0;
    uint64_t vmaddr_takey_shared = 0;
    TEE_Result ret;

    ret = huk_task_takey_msg_check(msg);
    if (ret != TEE_SUCCESS) {
        rsp->data.ret = ret;
        return ret;
    }

    if (msg->data.takey_msg.key_size < ITER_DERIVE_KEY2_SIZE) {
        rsp->data.ret = TEE_ERROR_BAD_PARAMETERS;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (huk_srv_map_from_task(sndr_pid, msg->data.takey_msg.key_buf,
                              msg->data.takey_msg.key_size, self_pid, &vmaddr_takey_shared) != 0) {
        tloge("huk service map takey2 buffer from 0x%x failed\n", sndr_pid);
        rsp->data.ret = TEE_ERROR_GENERIC;
        return rsp->data.ret;
    }

    if (huk_srv_map_from_task(sndr_pid, msg->data.takey_msg.salt_buf,
                              msg->data.takey_msg.salt_size, self_pid, &vmaddr_salt_shared) != 0) {
        tloge("huk service map salt2 buffer from 0x%x failed\n", sndr_pid);
        huk_srv_task_unmap(vmaddr_takey_shared, msg->data.takey_msg.key_size);
        rsp->data.ret = TEE_ERROR_GENERIC;
        return rsp->data.ret;
    }

    struct memref_t salt_shared = {0};
    struct memref_t takey_shared = {0};
    salt_shared.buffer = vmaddr_salt_shared;
    salt_shared.size = msg->data.takey_msg.salt_size;
    takey_shared.buffer = vmaddr_takey_shared;
    takey_shared.size = msg->data.takey_msg.key_size;
    ret = do_derive_takey2_iter(uuid, &salt_shared, &takey_shared,
        msg->data.takey_msg.outer_iter_num, msg->data.takey_msg.inner_iter_num);

    huk_srv_task_unmap(vmaddr_salt_shared, msg->data.takey_msg.salt_size);
    huk_srv_task_unmap(vmaddr_takey_shared, msg->data.takey_msg.key_size);
    rsp->data.ret = ret;
    return ret;
}

static TEE_Result huk_get_die_id(uint8_t *die_id, uint32_t die_id_size)
{
    (void)die_id_size;
    (void)die_id;
    tloge("OpenHarmony not support this function!!\n");
    return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result huk_derive_key(const uint8_t *salt_buff, uint32_t salt_len, uint8_t *key, uint32_t key_len)
{
    TEE_Result ret;
    struct memref_t salt = {0};
    struct memref_t cmac = {0};

    salt.buffer = (uintptr_t)salt_buff;
    salt.size = salt_len;

    cmac.buffer = (uintptr_t)key;
    cmac.size = key_len;
    ret = (TEE_Result)tee_crypto_derive_root_key(CRYPTO_KEYTYPE_HUK, &salt, &cmac, 1);
    if (ret != TEE_SUCCESS) {
        tloge("huk device id derive failed, ret %x\n", ret);
        return ret;
    }
    return TEE_SUCCESS;
}

static TEE_Result huk_task_deviceid_msg_check(const struct huk_srv_msg *msg)
{
    if ((msg == NULL) || (msg->data.deviceid_msg.buf == 0) ||
        (msg->data.deviceid_msg.size != TEE_DEVICE_ID_LEN)) {
        tloge("huk device id check messages failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result huk_task_get_deviceid(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
                                        uint32_t self_pid, uint32_t sndr_pid, const TEE_UUID *uuid)
{
    uint64_t vmaddr_devid_shared = 0;
    uint8_t dev_id[TEE_DEVICE_ID_LEN] = {0};

    (void)uuid;
    TEE_Result ret = huk_task_deviceid_msg_check(msg);
    if (ret != TEE_SUCCESS) {
        rsp->data.ret = TEE_ERROR_BAD_PARAMETERS;
        return rsp->data.ret;
    }

    uint32_t die_id_size = get_die_id_size();
    if ((die_id_size == INVALID_DIE_ID_SIZE) || (die_id_size > DIE_ID_SIZE_MAX)) {
        tloge("get die id size failed, size is %u\n", die_id_size);
        rsp->data.ret = TEE_ERROR_NOT_SUPPORTED;
        return rsp->data.ret;
    }
    uint8_t *die_id = TEE_Malloc(die_id_size, 0x0);
    if (die_id == NULL) {
        tloge("malloc die id failed!\n");
        rsp->data.ret = TEE_ERROR_OUT_OF_MEMORY;
        return rsp->data.ret;
    }
    if (huk_srv_map_from_task(sndr_pid, msg->data.deviceid_msg.buf,
                              msg->data.deviceid_msg.size, self_pid, &vmaddr_devid_shared) != 0) {
        tloge("huk service map device id buffer from 0x%x failed\n", sndr_pid);
        rsp->data.ret = TEE_ERROR_GENERIC;
        TEE_Free(die_id);
        return rsp->data.ret;
    }
    ret = huk_get_die_id(die_id, die_id_size);
    if (ret != TEE_SUCCESS)
        goto end_clean;

    ret = huk_derive_key(die_id, die_id_size, dev_id, (uint32_t)sizeof(dev_id));
    if (ret != TEE_SUCCESS)
        goto end_clean;

    if (memcpy_s((uint8_t *)(uintptr_t)vmaddr_devid_shared, msg->data.deviceid_msg.size,
                 dev_id, sizeof(dev_id)) != EOK)
        ret = TEE_ERROR_SECURITY;

end_clean:
    huk_srv_task_unmap(vmaddr_devid_shared, msg->data.deviceid_msg.size);
    rsp->data.ret = ret;
    (void)memset_s(dev_id, sizeof(dev_id), 0, sizeof(dev_id));
    TEE_Free(die_id);
    return ret;
}

static TEE_Result huk_task_provision_key(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
                                         uint32_t self_pid, uint32_t sndr_pid, const TEE_UUID *uuid)
{
    TEE_Result ret;
    errno_t rc;
    uint64_t vmaddr = 0;
    uint8_t key_temp[AES_CMAC_RESULT_SIZE_IN_BYTES] = {0};

    (void)uuid;
    if (msg == NULL || msg->data.provisionkey_msg.buf == 0 ||
        msg->data.provisionkey_msg.size < AES_CMAC_RESULT_SIZE_IN_BYTES) {
        tloge("huk provision key invalid msg\n");
        rsp->data.ret = TEE_ERROR_BAD_PARAMETERS;
        return rsp->data.ret;
    }

    if (!is_provisionkey_access(uuid)) {
        tloge("can not access this\n");
        rsp->data.ret = TEE_ERROR_ACCESS_DENIED;
        return rsp->data.ret;
    }
    if (huk_srv_map_from_task(sndr_pid, msg->data.provisionkey_msg.buf,
                              msg->data.provisionkey_msg.size, self_pid, &vmaddr) != 0) {
        tloge("huk service map provision key buffer from 0x%x failed\n", sndr_pid);
        rsp->data.ret = TEE_ERROR_GENERIC;
        return rsp->data.ret;
    }
    ret = (TEE_Result)tee_hal_get_provision_key(key_temp, AES_CMAC_RESULT_SIZE_IN_BYTES);
    if (ret != TEE_SUCCESS) {
        tloge("huk get provision key failed, %x\n", ret);
    } else {
        rc = memcpy_s((uint8_t *)(uintptr_t)vmaddr, msg->data.provisionkey_msg.size,
                      key_temp, AES_CMAC_RESULT_SIZE_IN_BYTES);
        if (rc != EOK)
            ret = TEE_ERROR_SECURITY;
        rsp->data.provisionkey_rsp.size = AES_CMAC_RESULT_SIZE_IN_BYTES;
    }
    (void)memset_s(key_temp, sizeof(key_temp), 0, sizeof(key_temp));
    huk_srv_task_unmap(vmaddr, msg->data.provisionkey_msg.size);
    rsp->data.ret = ret;
    return ret;
}

struct salt_ta_info {
    uint8_t salt_ta[KS_OFTS_TOTAL];
    uint32_t salt_ta_size;
};
/* assemble TA platform root key derive factor */
static TEE_Result ks_get_ta_plat_root_key_salt(struct salt_ta_info *ta_salt_info, const TEE_UUID *ta_uuid,
                                               uint32_t caller_level, const uint8_t *exinfo, uint32_t exinfo_size)
{
    errno_t rc;

    ta_salt_info->salt_ta[KS_OFTS_USAGE] = EKU_FOR_DERIVE_ECC;

    ta_salt_info->salt_ta[KS_OFTS_KDS_CALLER] = caller_level;

    rc = memcpy_s(ta_salt_info->salt_ta + KS_OFTS_TA_UUID, ta_salt_info->salt_ta_size - KS_OFTS_TA_UUID,
                  ta_uuid, sizeof(*ta_uuid));
    if (rc != EOK) {
        tloge("memory copy ta uuid failed");
        return TEE_ERROR_SECURITY;
    }

    rc = memcpy_s(ta_salt_info->salt_ta + KS_OFTS_EXINFO, ta_salt_info->salt_ta_size - KS_OFTS_EXINFO,
                  exinfo, exinfo_size);
    if (rc != EOK) {
        tloge("memory copy ta exinfo failed");
        return TEE_ERROR_SECURITY;
    }
    return TEE_SUCCESS;
}

#define SIZE_KOEM             16
#define DATA_TEE_PRK_DRV_V100 "salt for tee platform root key derive v1.00"
static int get_tee_plat_rootkey(uint8_t *key, uint32_t keysize)
{
    uint8_t k_oem_invalid[SIZE_KOEM] = { 0 };
    uint8_t k_oem[SIZE_KOEM] = { 0 };
    uint8_t data[] = DATA_TEE_PRK_DRV_V100;

    if (tee_hal_get_provision_key(k_oem, SIZE_KOEM) != 0) {
        tloge("huk get provision key failed\n");
        return -1;
    }
    if (TEE_MemCompare(k_oem, k_oem_invalid, sizeof(k_oem)) == 0) {
        tloge("get eom key failed!");
        return -1;
    }

    struct symmerit_key_t hmac_key = {0};
    struct memref_t data_in = {0};
    struct memref_t data_out = {0};
    hmac_key.key_buffer = (uintptr_t)k_oem;
    hmac_key.key_size = (uint32_t)sizeof(k_oem);
    data_in.buffer = (uintptr_t)data;
    data_in.size = (uint32_t)sizeof(data);
    data_out.buffer = (uintptr_t)key;
    data_out.size = keysize;
    int32_t hmac_rc = tee_crypto_hmac(CRYPTO_TYPE_HMAC_SHA512, &hmac_key, &data_in, &data_out, SOFT_CRYPTO);
    (void)memset_s(k_oem, sizeof(k_oem), 0, sizeof(k_oem));
    if (hmac_rc != 0) {
        tloge("hmac failed");
        return -1;
    }
    if (data_out.size != keysize) {
        tloge("hmac out len error, out_len=%u\n", data_out.size);
        (void)memset_s(key, keysize, 0, keysize);
        return -1;
    }
    return 0;
}

static TEE_Result ks_drv_ta_prk(uint8_t *keybuf, uint32_t keybytes, const struct huk_srv_msg *msg,
                                uint32_t caller_level, const TEE_UUID *ta_uuid)
{
    TEE_Result ret;
    uint8_t tee_pltrootkey[SIZE_HMAC512_OBYTES] = {0};
    struct salt_ta_info ta_salt_info            = { { 0 }, 0 };

    ta_salt_info.salt_ta_size = KS_OFTS_TOTAL;
    ret = ks_get_ta_plat_root_key_salt(&ta_salt_info, ta_uuid, caller_level,
                                       msg->data.plat_key_msg.exinfo, msg->data.plat_key_msg.exinfo_size);
    if (ret != TEE_SUCCESS) {
        tloge(" get_TA_PRK_salt failed\n");
        return ret;
    }

    if (keybytes != SIZE_HMAC512_OBYTES) {
        tloge("keybytes no supported\n");
        return TEE_ERROR_NOT_SUPPORTED;
    }

    if (get_tee_plat_rootkey(tee_pltrootkey, sizeof(tee_pltrootkey)) != 0) {
        tloge("huk get tee plat root key failed\n");
        return TEE_ERROR_GENERIC;
    }

    /* derive TA platform Root Key. */
    struct symmerit_key_t hmac_key;
    struct memref_t data_in;
    struct memref_t data_out;
    hmac_key.key_buffer = (uintptr_t)tee_pltrootkey;
    hmac_key.key_size = (uint32_t)sizeof(tee_pltrootkey);
    data_in.buffer = (uintptr_t)ta_salt_info.salt_ta;
    data_in.size = ta_salt_info.salt_ta_size;
    data_out.buffer = (uintptr_t)keybuf;
    data_out.size = 0;
    int32_t result = tee_crypto_hmac(CRYPTO_TYPE_HMAC_SHA512, &hmac_key, &data_in, &data_out, SOFT_CRYPTO);
    (void)memset_s(tee_pltrootkey, sizeof(tee_pltrootkey), 0, sizeof(tee_pltrootkey));
    if (result != 0) {
        tloge("hmac failed!");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static int32_t fill_ecc_key(uint8_t *key, uint32_t *key_len, uint32_t fill_size)
{
    if (*key_len == fill_size)
        return 0;
    if (*key_len > fill_size)
        return -1;
    uint32_t move_len = fill_size - *key_len;
    errno_t rc = memmove_s(key + move_len, *key_len, key, *key_len);
    if (rc != EOK) {
        tloge("ecc key fill failed");
        return -1;
    }

    rc = memset_s(key, fill_size, 0x0, move_len);
    if (rc != EOK) {
        tloge("ecc key fill failed");
        return -1;
    }
    *key_len = fill_size;
    return 0;
}

#define PRIV_KEY_OFFSET_NUM 2

static TEE_Result ks_drv_get_attr_buffer(uint32_t key_type, uint32_t keybuff_bytes,
                                         ecc_priv_key_t *ta_prk_priv, uint8_t *attr_buff, uint32_t attr_buff_size)
{
    errno_t ret;
    int32_t ret_c;
    ecc_pub_key_t ta_prk_pub = {0};

    switch (key_type) {
    case TEE_TYPE_ECDH_KEYPAIR:
    case TEE_TYPE_ECDSA_KEYPAIR:
        /* attr_buff's first 2/3 are for pubkey's X and Y */
        ret_c = fill_ecc_key(ta_prk_priv->r, &(ta_prk_priv->r_len), keybuff_bytes);
        if (ret_c != 0)
            return TEE_ERROR_SECURITY;
        ret = memcpy_s(attr_buff + keybuff_bytes * PRIV_KEY_OFFSET_NUM, /* the last 1/3 is for prikey's r */
                       attr_buff_size - keybuff_bytes * PRIV_KEY_OFFSET_NUM, ta_prk_priv->r, ta_prk_priv->r_len);
        if (ret != EOK) {
            tloge("copy r to buffer failed\n");
            return TEE_ERROR_SECURITY;
        }
        /* fall-through */
    case TEE_TYPE_ECDH_PUBLIC_KEY:
    case TEE_TYPE_ECDSA_PUBLIC_KEY:
        /* derive public key by swcrypto_engine will cost 300ms */
        ret_c = ecc_derive_public_key(ta_prk_priv, &ta_prk_pub);
        if (ret_c != 0) {
            tloge("derive ecc public key failed, ret = 0x%x\n", ret_c);
            return TEE_ERROR_GENERIC;
        }
        if (fill_ecc_key(ta_prk_pub.x, &(ta_prk_pub.x_len), keybuff_bytes) != 0 ||
            fill_ecc_key(ta_prk_pub.y, &(ta_prk_pub.y_len), keybuff_bytes) != 0)
            return TEE_ERROR_SECURITY;

        if (memcpy_s(attr_buff, attr_buff_size, ta_prk_pub.x, ta_prk_pub.x_len) != EOK ||
            memcpy_s(attr_buff + ta_prk_pub.x_len, attr_buff_size - ta_prk_pub.x_len,
                     ta_prk_pub.y, ta_prk_pub.y_len) != EOK) {
            tloge("copy pub failed");
            (void)memset_s(&ta_prk_pub, sizeof(ta_prk_pub), 0, sizeof(ta_prk_pub));
            return TEE_ERROR_GENERIC;
        }
        break;

    default:
        tloge("unkown key type, key type is %u\n", key_type);
        return TEE_ERROR_SECURITY;
    }
    (void)memset_s(&ta_prk_pub, sizeof(ta_prk_pub), 0, sizeof(ta_prk_pub));
    return TEE_SUCCESS;
}

static TEE_Result ks_drv_ecc_ta_pk(const struct huk_srv_msg *msg, uint32_t caller_level, const TEE_UUID *ta_uuid,
                                   uint8_t *attr_buff, uint32_t attr_size)
{
    uint8_t keybuf[SIZE_HMAC512_OBYTES] = {0};
    ecc_priv_key_t ta_prk_priv          = {0};
    TEE_Result ret;
    int ecc_ret;

    ret = ks_drv_ta_prk(keybuf, (uint32_t)sizeof(keybuf), msg, caller_level, ta_uuid);
    if (ret != TEE_SUCCESS) {
        tloge("huk ta prk failed.\n");
        return ret;
    }

    ecc_ret = derive_ecc_private_key_from_huk(&ta_prk_priv, keybuf, (uint32_t)sizeof(keybuf));
    /* clear ta_pltrootkey in memory */
    (void)memset_s(keybuf, sizeof(keybuf), 0, sizeof(keybuf));
    if (ecc_ret != 0) {
        tloge("huk derive ecc private key failed");
        return TEE_ERROR_GENERIC;
    }

    ret = ks_drv_get_attr_buffer(msg->data.plat_key_msg.keytype, msg->data.plat_key_msg.keysize,
                                 &ta_prk_priv, attr_buff, attr_size);

    (void)memset_s(ta_prk_priv.r, ta_prk_priv.r_len, 0, ta_prk_priv.r_len);

    return ret;
}

static uint32_t ks_get_ta_level(const TEE_UUID *caller_uuid)
{
    uint32_t level;

    /* implement level whitelist. first add HDCP_UUID */
    if (is_ta_access_kds_permission(caller_uuid)) {
        level = LEVEL_3ST;
    } else {
        level = LEVEL_UND;
    }

    return level;
}

static uint32_t ks_get_caller_level(uint32_t csc_type, const TEE_UUID *csc_uuid, const TEE_UUID *ta_uuid)
{
    uint32_t level;

    if (is_kds_uuid(ta_uuid)) {
        /* for KDS TA */
        if (csc_type == SESSION_FROM_CA) /* CA2TA for KDS TA */
            level = LEVEL_KCA;
        else
            level = ks_get_ta_level(csc_uuid); /* TA2TA for KDS TA */
    } else {
        /* for normal TA */
        level = LEVEL_COM;
    }
    return level;
}

#define PUBLIC_KEY_COUNT 2U
#define KEY_PAIR_COUNT   3U

static uint32_t ks_deriveta_get_count(uint32_t key_type)
{
    uint32_t attr_count;

    /*
     * attr_count here is only X, Y, PrivateExpont, with out CURVE_TYPE;
     * so (attr_count+1) is actual Attribute count for object.
     */
    switch (key_type) {
    case (uint32_t)TEE_TYPE_ECDH_PUBLIC_KEY:
    case (uint32_t)TEE_TYPE_ECDSA_PUBLIC_KEY:
        attr_count = PUBLIC_KEY_COUNT;
        break;
    case (uint32_t)TEE_TYPE_ECDH_KEYPAIR:
    case (uint32_t)TEE_TYPE_ECDSA_KEYPAIR:
        attr_count = KEY_PAIR_COUNT;
        break;
    default:
        tloge("objectType is not supported\n");
        attr_count = 0;
    }

    return attr_count;
}

/* hdcp TA -> kds TA -> tks */
static TEE_Result ks_deriveta_platkeys(const struct huk_srv_msg *msg, const TEE_UUID *ta_uuid, uint8_t *attr_buff,
                                       uint32_t attr_size)
{
    TEE_Result ret = TEE_SUCCESS;
    uint32_t caller_level;
    uint32_t attr_count;
    const TEE_UUID csc_uuid = { 0, 0, 0, { 0 } };
    if (memcpy_s((void *)&csc_uuid, sizeof(csc_uuid), &(msg->data.plat_key_msg.csc_uuid),
                 sizeof(msg->data.plat_key_msg.csc_uuid)) != EOK)
        return TEE_ERROR_SECURITY;

    if (attr_buff == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    attr_count = ks_deriveta_get_count(msg->data.plat_key_msg.keytype);
    if (attr_count == 0)
        return TEE_ERROR_NOT_SUPPORTED;

    switch (msg->data.plat_key_msg.keysize) {
    case SIZE_ECC256:
        if (attr_size != (msg->data.plat_key_msg.keysize * attr_count)) {
            tloge("attribution size inconsistency\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }
        break;
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* get caller level as key derive factor */
    caller_level = ks_get_caller_level(msg->data.plat_key_msg.csc_type, &csc_uuid, ta_uuid);
    if (caller_level == LEVEL_ERR) {
        tloge("caller level for KDS is not defined.\n");
        return TEE_ERROR_NO_DATA;
    }

    /* call the real worker */
    switch (msg->data.plat_key_msg.keytype) {
    case (uint32_t)TEE_TYPE_ECDH_PUBLIC_KEY:
    case (uint32_t)TEE_TYPE_ECDSA_PUBLIC_KEY:
    case (uint32_t)TEE_TYPE_ECDH_KEYPAIR:
    case (uint32_t)TEE_TYPE_ECDSA_KEYPAIR:
        ret = ks_drv_ecc_ta_pk(msg, caller_level, ta_uuid, attr_buff, attr_size);
        break;
    default:
        tloge("object type is not supported.\n");
        ret = TEE_ERROR_NOT_SUPPORTED;
        break;
    }

    return ret;
}

static TEE_Result huk_task_derive_plat_root_key_check_msg(const struct huk_srv_msg *msg)
{
    TEE_Result ret;

    if (msg->data.plat_key_msg.exinfo_size == 0 || msg->data.plat_key_msg.exinfo_size > SIZE_MAX_EXINFO) {
        tloge("huk msg exinfo size is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (msg->data.plat_key_msg.attri_buff == 0) {
        tloge("huk invalid msg\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (msg->data.plat_key_msg.csc_type == SESSION_FROM_UNKNOWN) {
        tloge("huk msg csc type is invalid \n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((msg->data.plat_key_msg.keytype == (uint32_t)TEE_TYPE_ECDH_PUBLIC_KEY ||
         msg->data.plat_key_msg.keytype == (uint32_t)TEE_TYPE_ECDSA_PUBLIC_KEY) &&
        msg->data.plat_key_msg.attri_size == SIZE_ECC256 * ATTR_BUFFER_SIZE_PUBLIC) {
        ret = TEE_SUCCESS;
    } else if ((msg->data.plat_key_msg.keytype == (uint32_t)TEE_TYPE_ECDH_KEYPAIR ||
                msg->data.plat_key_msg.keytype == (uint32_t)TEE_TYPE_ECDSA_KEYPAIR) &&
               msg->data.plat_key_msg.attri_size == SIZE_ECC256 * ATTR_BUFFER_SIZE_PAIR) {
        ret = TEE_SUCCESS;
    } else {
        tloge("huk input args not supported\n");
        return TEE_ERROR_NOT_SUPPORTED;
    }

    return ret;
}

static TEE_Result huk_task_derive_plat_root_key(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
                                                uint32_t self_pid, uint32_t sndr_pid, const TEE_UUID *uuid)
{
    errno_t rc;
    uint8_t *tmpbuf = NULL;
    uint32_t tmpbuf_size;
    uint64_t vmaddr = 0;
    TEE_Result ret;

    ret = huk_task_derive_plat_root_key_check_msg(msg);
    if (ret != TEE_SUCCESS) {
        rsp->data.ret = ret;
        return ret;
    }
    tmpbuf_size = msg->data.plat_key_msg.attri_size;
    tmpbuf = TEE_Malloc(tmpbuf_size, 0);
    if (tmpbuf == NULL) {
        tloge("huk malloc outbuf failed.\n");
        rsp->data.ret = TEE_ERROR_OUT_OF_MEMORY;
        return rsp->data.ret;
    }
    if (huk_srv_map_from_task(sndr_pid, msg->data.plat_key_msg.attri_buff,
                              msg->data.plat_key_msg.attri_size, self_pid, &vmaddr) != 0) {
        tloge("huk service map plat key buffer from 0x%x failed\n", sndr_pid);
        rsp->data.ret = TEE_ERROR_GENERIC;
        TEE_Free(tmpbuf);
        return rsp->data.ret;
    }

    rsp->data.ret = ks_deriveta_platkeys(msg, uuid, tmpbuf, tmpbuf_size);

    if (rsp->data.ret == TEE_SUCCESS) {
        rc = memcpy_s((uint8_t *)(uintptr_t)vmaddr, msg->data.plat_key_msg.attri_size,
                      tmpbuf, msg->data.plat_key_msg.attri_size);
        if (rc != EOK) {
            tloge("memory copy buffer failed. ret = %x.\n", rsp->data.ret);
            rsp->data.ret = TEE_ERROR_SECURITY;
        }
    } else {
        tloge("derive ta plat key failed.\n");
    }
    huk_srv_task_unmap(vmaddr, msg->data.plat_key_msg.attri_size);
    (void)memset_s(tmpbuf, tmpbuf_size, 0, tmpbuf_size);
    TEE_Free(tmpbuf);
    return rsp->data.ret;
}

static const struct cmd_operate_config_s g_cmd_operate_config[] = {
    { CMD_HUK_DERIVE_TAKEY,         huk_task_derive_takey },
    { CMD_HUK_GET_DEVICEID,         huk_task_get_deviceid },
    { CMD_HUK_PROVISION_KEY,        huk_task_provision_key },
    { CMD_HUK_DERIVE_PLAT_ROOT_KEY, huk_task_derive_plat_root_key },
    { CMD_HUK_DERIVE_TAKEY2,        huk_task_derive_takey2_iter },
};
#define CMD_COUNT (sizeof(g_cmd_operate_config) / sizeof(g_cmd_operate_config[0]))
static void handle_cmd(const struct huk_srv_msg *msg, cref_t msghdl, uint32_t sndr_pid,
                       uint16_t msg_type, const TEE_UUID *uuid)
{
    uint32_t cmd_id;
    uint32_t self_pid;
    int32_t rc;
    struct huk_srv_rsp rsp;
    uint32_t i;

    (void)memset_s(&rsp, sizeof(rsp), 0, sizeof(rsp));
    rsp.data.ret = TEE_ERROR_GENERIC;
    cmd_id = msg->header.send.msg_id;
    self_pid = get_selfpid();
    if (self_pid == SRE_PID_ERR) {
        tloge("huk service get self pid error\n");
        rsp.data.ret = TEE_ERROR_GENERIC;
        goto ret_flow;
    }

    for (i = 0; i < CMD_COUNT; i++) {
        if ((cmd_id != g_cmd_operate_config[i].cmd_id) || (g_cmd_operate_config[i].operate_func == NULL))
            continue;
        rsp.data.ret = g_cmd_operate_config[i].operate_func(msg, &rsp, self_pid, sndr_pid, uuid);
        if (rsp.data.ret != TEE_SUCCESS) {
            if (rsp.data.ret == TEE_ERROR_NOT_SUPPORTED)
                tlogw("cmd 0x%x is not supported\n", cmd_id);
            else
                tloge("cmd 0x%x error, ret = 0x%x\n", cmd_id, rsp.data.ret);
        }
        break;
    }
    if (i == CMD_COUNT)
        tloge("the cmd id 0x%x is not supported\n", cmd_id);

ret_flow:
    if (msg_type == HM_MSG_TYPE_CALL) {
        rc = hm_msg_reply(msghdl, &rsp, sizeof(rsp));
        if (rc != 0)
            tloge("reply error 0x%x\n", rc);
    }
}

#ifdef CONFIG_DYNLINK
__attribute__((section(".magic"), visibility("default")))
const char g_magic_string[MAGIC_STR_LEN] = "Dynamically linked.";
#endif

__attribute__((visibility ("default"))) void tee_task_entry(int init_build)
{
    struct huk_srv_msg msg;
    spawn_uuid_t uuid;
    cref_t ch = 0;
    msginfo_t info = {0};
    int32_t ret_hm;
    struct channel_ipc_args ipc_args = {0};

    (void)memset_s(&msg, sizeof(msg), 0, sizeof(msg));
    if (init_build == 0)
        huk_clear_ta_bss();

    cref_t msghdl = huk_get_mymsghdl();
    if (is_ref_err(msghdl) != 0) {
        tloge("Cannot create msg hdl, %s\n", hmapi_strerror((int)msghdl));
        hm_exit((int)msghdl);
    }

    if (hm_create_ipc_native(HUK_PATH, &ch) != 0) {
        tloge("create main thread native channel failed!\n");
        hm_exit(-1);
    }

    if (ac_init_simple() != 0) {
        tloge("ac init error\n");
        hm_exit(-1);
    }

    ret_hm = hm_tamgr_register(HUK_TASK_NAME);
    if (ret_hm != 0) {
        tloge("hm tamgr register fail is %d!\n", ret_hm);
        hm_exit(-1);
    }

    ipc_args.channel = ch;
    ipc_args.recv_buf = &msg;
    ipc_args.recv_len = sizeof(msg);
    while (1) {
        ret_hm = hm_msg_receive(&ipc_args, msghdl, &info, 0, -1);
        if (ret_hm < 0) {
            tloge("huk service: message receive failed, %llx, %s\n", ret_hm, hmapi_strerror(ret_hm));
            continue;
        }

        if (hm_getuuid((pid_t)info.src_cred.pid, &uuid) != 0)
            tloge("huk service get uuid failed\n");

        if (info.src_cred.pid == 0)
            handle_cmd(&msg, msghdl, GLOBAL_HANDLE, info.msg_type, &(uuid.uuid));
        else
            handle_cmd(&msg, msghdl, (uint32_t)hmpid_to_pid(TCBCREF2TID(info.src_tcb_cref), info.src_cred.pid),
                       info.msg_type, &(uuid.uuid));
    }

    tloge("huk service abort!\n");
}
