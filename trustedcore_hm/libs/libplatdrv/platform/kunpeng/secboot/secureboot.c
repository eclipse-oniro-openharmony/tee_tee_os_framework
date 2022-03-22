/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: get oemkey for kunpeng platform
 * Author: zhanglinhao zhanglinhao@huawei.com
 * Create: 2020-06
 */
#include "secureboot.h"
#include <string.h>
#include <tee_log.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include <hmdrv_stub.h>
#include <securec.h>
#include <hm_mman.h>
#include "sre_task.h"
#include "drv_module.h"
#include "boot_sharedmem.h"
#include "getcert.h"
#include "oemkey_driver_hal.h"

static struct tee_secureinfo g_secinfo;

static int32_t secboot_check_valid(void)
{
    if (g_secinfo.head_magic != SECBOOT_MAGIC_NUM || g_secinfo.tail_magic != SECBOOT_MAGIC_NUM) {
        tloge("secinfo error, maybe uninitialized or modified, head magic 0x%x, tail magic 0x%x\n",
              g_secinfo.head_magic, g_secinfo.tail_magic);
        return SECBOOT_RET_FAILURE;
    }
    return SECBOOT_RET_SUCCESS;
}

static uint32_t secboot_get_secinfo_provisionkey(uint8_t *pkey, uint32_t len)
{
    errno_t rc;
    int32_t ret;

    if ((pkey == NULL) || (len < sizeof(g_secinfo.provision_key))) {
        tloge("param error\n");
        return SECBOOT_RET_PARAM_ERROR;
    }

    ret = secboot_check_valid();
    if (ret != SECBOOT_RET_SUCCESS)
        return ret;

    rc = memcpy_s(pkey, len, g_secinfo.provision_key, sizeof(g_secinfo.provision_key));
    if (rc != EOK) {
        tloge("error get sec mem info\n");
        return SECBOOT_RET_FAILURE;
    }

    return SECBOOT_RET_SUCCESS;
}

#if defined(_PRINT_ALL_INFO_)
static void secboot_print_secinfo(void)
{
    uint32_t ret;
    uint32_t i;
    uint8_t provision_key[OEMKEY_SIZE] = { 0 };

    ret = secboot_get_secinfo_provisionkey(provision_key, sizeof(provision_key));
    if (ret != SECBOOT_RET_SUCCESS) {
        tloge("get secinfo fail\n");
        return;
    }

    for (i = 0; i < OEMKEY_SIZE; i++)
        tloge("[secinfo] provision_key:%d: 0x%x\n", i, provision_key[i]);
}
#endif

static void secboot_get_secinfo(void)
{
    int32_t ret;
    uint32_t buffer_size = sizeof(g_secinfo);
    /* clear secboot secinfo zero */
    (void)memset_s(&g_secinfo, sizeof(g_secinfo), 0, sizeof(g_secinfo));

    /* map secboot secinfo ddr memory address */
    ret = get_tlv_shared_mem_drv(SHARED_MEM_SECBOOT, strlen(SHARED_MEM_SECBOOT),
                                 &g_secinfo, &buffer_size, true);
    if (ret != SECBOOT_RET_SUCCESS) {
        tloge("get sharemem info failed, ret is 0x%x\n", ret);
        return;
    }

    ret = secboot_check_valid();
    if (ret != SECBOOT_RET_SUCCESS)
        tloge("get info fail\n");

#if defined(_PRINT_ALL_INFO_)
    /* print secinfo */
    secboot_print_secinfo();
#endif
}

static void get_sglist()
{
    struct memory_sglist mem_list;
    (void)memset_s(&mem_list, sizeof(mem_list), 0, sizeof(mem_list));
    int32_t ret;
    uint32_t i;
    uint32_t buffer_size = sizeof(mem_list);
    ret = get_tlv_shared_mem_drv(SHARED_MEM_MEMORY_SGLIST,
                                 strlen(SHARED_MEM_MEMORY_SGLIST),
                                 &mem_list,
                                 &buffer_size,
                                 true);
    if (ret != 0) {
        tloge("get MEMORY_SGLIST sharedmem failed\n");
        return;
    }

    if (mem_list.magic != SECBOOT_MAGIC_NUM) {
        tloge("error memory list, magic=0x%x\n", mem_list.magic);
        return;
    }

    tlogd("mem_list.num=%llu\n", mem_list.num);

    if (mem_list.num > SGLIST_MAX_LEN) {
        tloge("mem_list.num error\n");
        return;
    }

    for (i = 0; i < mem_list.num; i++) {
        tlogd("add free mem %d: start=0x%llx, size=0x%llx\n",
              i, mem_list.memory[i].start, mem_list.memory[i].size);
        ret = hm_add_free_mem(mem_list.memory[i].start,  mem_list.memory[i].size);
        if (ret != 0) {
            tloge("add free mem %d failed\n", i);
            continue;
        }
        tlogd("mem_list.num %d add successful\n", i);
    }
}

uint32_t get_provision_key(uint8_t *poemkey, size_t key_size)
{
    uint32_t ret;

    if (poemkey == NULL || key_size != OEMKEY_SIZE) {
        tloge("param error\n");
        return SECBOOT_RET_PARAM_ERROR;
    }
    ret = secboot_get_secinfo_provisionkey(poemkey, key_size);
    if (ret != SECBOOT_RET_SUCCESS)
        tloge("failed to get provision key, ret=0x%x\n", ret);

    return ret;
}

static struct oemkey_ops_t g_oemkey_ops = {
    get_provision_key,
};

int32_t secboot_info_init(void)
{
    secboot_get_secinfo();
    get_sglist();
    return register_oemkey_ops(SEC_OEMKEY_FLAG, &g_oemkey_ops);
}

int32_t secureboot_syscall(int32_t swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t ret;

    if (params == NULL || params->args == 0) {
        tloge("invalid input\n");
        return -1;
    }

    uint64_t *args = (uint64_t *)(uintptr_t)(params->args);

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_GET_CERT, permissions, CERT_KEY_GROUP_PERMISSION)
        if (args[1] > 0) {
            ACCESS_CHECK_A64(args[0], args[1]);
            ACCESS_WRITE_RIGHT_CHECK(args[0], args[1]);
        }
        ret = get_certkey_info((uint8_t *)(uintptr_t)args[0], (size_t)args[1]);
        args[0] = (uint32_t)ret;
        SYSCALL_END;
    default:
            return -1;
    }
    return 0;
}

DECLARE_TC_DRV(
    secboot_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    secboot_info_init,
    NULL,
    secureboot_syscall,
    NULL,
    NULL
);
