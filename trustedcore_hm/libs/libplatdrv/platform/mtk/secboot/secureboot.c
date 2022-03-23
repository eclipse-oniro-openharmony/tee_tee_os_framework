/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: secureboot defines
 * Author: QiShuai qishuai@huawei.com
 * Create: 2020-08-09
 */
#include "secureboot.h"
#include <tee_log.h>
#include <sre_syscalls_id_ext.h>
#include <sre_syscalls_id.h>
#include <kernel/sre_access_control.h>
#include <hmdrv_stub.h>
#include "drv_module.h"
#include "boot_sharedmem.h"
#include "oemkey_driver_hal.h"

/*
 * on hisi-platfrom Die id is 5*4=20 bytes.
 * on MTK  Die id is 8*4=32 bytes.
 * In Userpace, Die id size is defined in TEE/tee_ext_api.h
 */
#define DIE_ID_SIZE 32U
#define SECBOOT_MAGIC_NUM  0x55AA55AA
#define PROVISION_KEY_SIZE 16U
#define RESERVED_BYTES 10U

struct tee_secure_info {
    uint8_t  provision_key[PROVISION_KEY_SIZE];
    uint32_t head_magic;
    uint16_t oem_id;
    uint16_t hw_id;
    uint8_t  sec_cfg;
    uint8_t  lock_status;
    uint8_t  first_vernum;
    uint8_t  second_vernum;
    uint8_t  unsec_vernum;
    uint8_t  die_id[DIE_ID_SIZE];
    uint8_t  fbe2_flag;
    uint8_t  reserved[RESERVED_BYTES];
    uint32_t tail_magic;
} __attribute__((__packed__));

static struct tee_secure_info g_secboot_secinfo;

#ifdef SECUREBOOT_PRINT_ALL_INFO
static void secboot_print_secinfo(void);
#endif

static uint32_t secboot_check_secinfo_magic(void)
{
    if ((g_secboot_secinfo.head_magic != SECBOOT_MAGIC_NUM) ||
        (g_secboot_secinfo.tail_magic != SECBOOT_MAGIC_NUM)) {
        tloge("secboot secinfo error, maybe uninitialized or modified, head_magic 0x%x, tail_magic 0x%x\n",
            g_secboot_secinfo.head_magic, g_secboot_secinfo.tail_magic);
        return SECBOOT_RET_FAILURE;
    }

    return SECBOOT_RET_SUCCESS;
}

static void secboot_get_secinfo(void)
{
    int32_t ret;
    uint32_t uret;

    tloge("enter get secinfo");

    /* clear secboot secinfo zero */
    ret = memset_s((void *)&g_secboot_secinfo, sizeof(g_secboot_secinfo), 0, sizeof(g_secboot_secinfo));
    if (ret != EOK)
        tloge("memset secboot secinfo failed\n");

    /* map secboot secinfo ddr memory address */
    ret = get_shared_mem_info(TEEOS_SHARED_MEM_SECBOOT, (uint32_t *)&g_secboot_secinfo, sizeof(g_secboot_secinfo));
    if (ret != 0) {
        tloge("Get sharemem info Failed, ret is 0x%x\n", ret);
        return;
    }

    uret = secboot_check_secinfo_magic();
    if (uret != SECBOOT_RET_SUCCESS)
        tloge("check secinfo magic fail\n");
    else
        tlogd("check secinfo magic succ\n");

    /* print secinfo */
#ifdef SECUREBOOT_PRINT_ALL_INFO
    secboot_print_secinfo();
#endif
}

static uint32_t secboot_get_secinfo_dieid(uint8_t *pdieid, uint32_t len)
{
    if ((pdieid == NULL) || (len < sizeof(g_secboot_secinfo.die_id))) {
        tloge("get dieid param error\n");
        return SECBOOT_RET_PARAM_ERROR;
    }

    if (secboot_check_secinfo_magic() != SECBOOT_RET_SUCCESS)
        return SECBOOT_RET_FAILURE;

    int32_t ret = memcpy_s((void *)pdieid, len, (void *)g_secboot_secinfo.die_id, sizeof(g_secboot_secinfo.die_id));
    if (ret != EOK) {
        tloge("copy dieid failed\n");
        return SECBOOT_RET_FAILURE;
    }

    tlogd("get dieid success\n");

    return SECBOOT_RET_SUCCESS;
}

static uint32_t secboot_get_secinfo_provisionkey(uint8_t *pkey, uint32_t len)
{
    if ((pkey == NULL) || (len < sizeof(g_secboot_secinfo.provision_key))) {
        tloge("get provision key param error\n");
        return SECBOOT_RET_PARAM_ERROR;
    }

    if (secboot_check_secinfo_magic() != SECBOOT_RET_SUCCESS)
        return SECBOOT_RET_FAILURE;

    int32_t ret = memcpy_s((void *)pkey, len, (void *)g_secboot_secinfo.provision_key,
        sizeof(g_secboot_secinfo.provision_key));
    if (ret != EOK) {
        tloge("copy provison key failed\n");
        return SECBOOT_RET_FAILURE;
    }

    tlogd("get provisionkey success\n");

    return SECBOOT_RET_SUCCESS;
}

static uint32_t get_provision_key(uint8_t *oemkey, size_t len)
{
    uint32_t ret = secboot_get_secinfo_provisionkey(oemkey, len);
    if (ret != SECBOOT_RET_SUCCESS)
        tloge("failed to get provision key, ret=0x%x\n", ret);

    return ret;
}

static struct oemkey_ops_t g_oemkey_ops = {
    get_provision_key,
};

int32_t secboot_init(void)
{
    secboot_get_secinfo();
    return register_oemkey_ops(SEC_OEMKEY_FLAG, &g_oemkey_ops);
}

#ifdef SECUREBOOT_PRINT_ALL_INFO
static void secboot_print_secinfo(void)
{
    uint32_t ret = 0;
    uint32_t i;
    uint8_t die_id[DIE_ID_SIZE] = {0};
    uint8_t provision_key[PROVISION_KEY_SIZE] = {0};

    ret += secboot_get_secinfo_dieid(die_id, sizeof(die_id));
    ret += secboot_get_secinfo_provisionkey(provision_key, sizeof(provision_key));
    if (ret != SECBOOT_RET_SUCCESS) {
        tloge("print get secinfo fail\n");
        return;
    }

    /* print secinfo */
    for (i = 0; i < DIE_ID_SIZE; i++)
        tloge("[secinfo] die_id[%d]: 0x%x\n", i, die_id[i]);

    for (i = 0; i < PROVISION_KEY_SIZE; i++)
        tloge("[secinfo] provision_key[%d]: 0x%x\n", i, provision_key[i]);
}
#endif

int32_t secureboot_syscall(int32_t swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t uwret;

    if ((params == NULL) || (params->args == 0)) {
        tloge("secureboot syscall invalid input\n");
        return -1;
    }

    uint64_t *args = (uint64_t *)(uintptr_t)(params->args);

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_TEE_HAL_GET_DIEID, permissions,
                           GENERAL_GROUP_PERMISSION) /*lint !e835 !e587 !e774 */
        ACCESS_CHECK_A64(args[0], DIE_ID_SIZE);
        ACCESS_WRITE_RIGHT_CHECK(args[0], DIE_ID_SIZE);
        uwret = secboot_get_secinfo_dieid((uint8_t *)(uintptr_t)args[0], DIE_ID_SIZE);
        args[0] = uwret;
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
    secboot_init,
    NULL,
    secureboot_syscall,
    NULL,
    NULL
);
