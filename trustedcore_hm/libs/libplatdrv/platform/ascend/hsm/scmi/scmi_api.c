/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
* Description: scmi source file
* Author: huawei
* Create: 2019/12/25
*/

#include <register_ops.h>
#include <pthread.h>
#include <drv_mem.h>
#include <drv_module.h>
#include <sre_access_control.h>
#include <hmdrv_stub.h>
#include <sre_syscalls_id_ext.h>
#include <secure_gic_common.h>
#include <sre_hwi.h>
#include <drv_task_map.h>
#include <time.h>
#include <tee_log.h>
#include <tee_defines.h>

#include "driver_common.h"
#include "hsm_dev_id.h"
#include "scmi.h"
#include "scmi_api.h"

#include "securec.h"

static pthread_mutex_t g_scmi_thread_mutex[DEV_NUM_MAX] = {
    PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER
};

static uint32_t g_scmi_interrupt_status[DEV_NUM_MAX] =  { 0 };

static uint32_t g_channels_state[DEV_NUM_MAX][MAILBOX_CHANNEL_MAX] = {
    {SCMI_CHANNEL_FREE, SCMI_CHANNEL_FREE, SCMI_CHANNEL_FREE, SCMI_CHANNEL_FREE},
    {SCMI_CHANNEL_FREE, SCMI_CHANNEL_FREE, SCMI_CHANNEL_FREE, SCMI_CHANNEL_FREE},
};

STATIC uint32_t scmi_drv_channel_verify(uint32_t dev_id, uint32_t channel)
{
    uint32_t ret;

    ret = drv_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if (channel >= MAILBOX_CHANNEL_MAX) {
        tloge("channel is invaild %d.\n", channel);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

STATIC void scmi_set_interrupt_status(uint32_t dev_id, uint32_t channel, uint32_t status)
{
    g_channels_state[dev_id][channel] = status;
}

STATIC uint32_t scmi_get_interrupt_status(uint32_t dev_id, uint32_t channel)
{
    return g_channels_state[dev_id][channel];
}

STATIC void scmi0_hiss_handler(void)
{
    uint32_t dev_num = scmi_get_dev_number();

    for (uint32_t i = 0; i < dev_num; i++) {
        g_scmi_interrupt_status[i] = scmi_get_channel_notifyint(0);
        if (g_scmi_interrupt_status[i] != 0) {
            write32(SCMI_NOTIFYINT_CLR + i * DEVICE_ADDR_OFFSET, g_scmi_interrupt_status[i]);
            return;
        }
    }
}

STATIC uint32_t secure_scmi_handler_init(void)
{
    uint32_t ret;
    uint32_t init_array[] = {INT_SCMI0_HISS_NUMBLER, INT_SCMI0_HISS_NUMBLER_P1};

    uint32_t dev_num = scmi_get_dev_number();

    for (uint32_t i = 0; i < dev_num; i++) {
        /* for mtk, freerun and tick timer use the same irq num */
        ret = SRE_HwiCreate(init_array[i], HWI_DEF_SCMI_PRIORITY, INT_SECURE,
                            (HWI_PROC_FUNC)scmi0_hiss_handler, INT_FUN_SCMI);
        if (ret != SRE_OK) {
            tloge("scmi %d interrupt creat failed, 0x%x.\n", i, ret);
            return ret;
        }
    }

    return TEE_SUCCESS;
}

STATIC uint32_t secure_scmi_interrupt_enable(void)
{
    uint32_t init_array[] = {INT_SCMI0_HISS_NUMBLER, INT_SCMI0_HISS_NUMBLER_P1};

    uint32_t dev_num = scmi_get_dev_number();

    /* enable SCMI */
    for (uint32_t i = 0; i < dev_num; i++) {
        uint32_t ret = SRE_HwiEnable(init_array[i]);
        if (ret != SRE_OK) {
            tloge("scmi interrupt %d register failed, 0x%x.\n", ret);
            return ret;
        }
    }

    return TEE_SUCCESS;
}

uint32_t scmi_interrupt_init(void)
{
    uint32_t ret;

    ret = secure_scmi_handler_init();
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = secure_scmi_interrupt_enable();
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC void scmi_channel_interrupt_set(uint32_t dev_id, uint32_t channel)
{
    /* enable channel[0~3] */
    scmi_set_channel_enable(dev_id, channel);

    /* close mask doorbell/doorbellack/notifyint */
    scmi_set_channel_doorbell_msk(dev_id, ~(CHANNEL_TO_BIT(channel)));
    scmi_set_channel_doorbellack_msk(dev_id, ~(CHANNEL_TO_BIT(channel)));
    scmi_set_channel_notifyint_msk(dev_id, ~(CHANNEL_TO_BIT(channel)));
}

STATIC uint32_t scmi_channel_open(uint32_t dev_id, uint32_t channel)
{
    uint32_t ret;
    int rc;
    uint32_t val;

    ret = scmi_drv_channel_verify(dev_id, channel);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    rc = pthread_mutex_lock(&g_scmi_thread_mutex[dev_id]);
    if (rc != TEE_SUCCESS) {
        tloge("get scmi thread mutex failed: 0x%x.\n", rc);
        return rc;
    }

    ret = scmi_get_interrupt_status(dev_id, channel);
    if (ret != SCMI_CHANNEL_FREE) {
        tloge("scmi state is out-of-order, 0x%x.\n", ret); /* cannot return ret */
        goto exit;
    }

    scmi_set_interrupt_status(dev_id, channel, SCMI_CHANNEL_OCCUPIED);

    scmi_channel_interrupt_set(dev_id, channel);

    val = scmi_get_channel_enable(dev_id);
    if (val != (CHANNEL_TO_BIT(channel))) {
        tloge("check channel enable failed, 0x%x.\n", val);
        goto exit;
    }

    val = scmi_get_channel_doorbell_msk(dev_id);
    if (val != ~(CHANNEL_TO_BIT(channel))) {
        tloge("check doorbell msk failed, 0x%x.\n", val);
        goto exit;
    }

    val = scmi_get_channel_doorbellack_msk(dev_id);
    if (val != ~(CHANNEL_TO_BIT(channel))) {
        tloge("check doorbellack msk failed, 0x%x.\n", val);
        goto exit;
    }

    val = scmi_get_channel_notifyint_msk(dev_id);
    if (val != ~(CHANNEL_TO_BIT(channel))) {
        tloge("check notifyint msk failed, 0x%x.\n", val);
        goto exit;
    }

    return TEE_SUCCESS;

exit:
    rc = pthread_mutex_unlock(&g_scmi_thread_mutex[dev_id]);
    if (rc != TEE_SUCCESS) {
        tloge("release scmi thread mutex failed: 0x%x.\n", rc);
        return rc;
    }

    return TEE_ERROR_BAD_STATE;
}

STATIC uint32_t scmi_channel_close(uint32_t dev_id, uint32_t channel)
{
    uint32_t ret;

    ret = scmi_drv_channel_verify(dev_id, channel);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = scmi_get_interrupt_status(dev_id, channel);
    if (ret != SCMI_CHANNEL_OCCUPIED) {
        tloge("scmi state is out-of-order, 0x%x.\n", ret);
        return TEE_ERROR_BAD_STATE; /* cannot return ret */
    }

    /* mask doorbellack/msk/notifyint */
    scmi_set_channel_doorbell_msk(dev_id, CHANNEL_TO_BIT(channel));
    scmi_set_channel_doorbellack_msk(dev_id, CHANNEL_TO_BIT(channel));
    scmi_set_channel_notifyint_msk(dev_id, CHANNEL_TO_BIT(channel));

    /* disable channel */
    scmi_set_channel_disable(dev_id, channel);
    scmi_set_interrupt_status(dev_id, channel, SCMI_CHANNEL_FREE);

    ret = pthread_mutex_unlock(&g_scmi_thread_mutex[dev_id]);
    if (ret != TEE_SUCCESS) {
        tloge("release scmi thread mutex failed: %d\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t scmi_channel_send_data(uint32_t dev_id, uint32_t channel, uint8_t *buf, uint32_t len)
{
    uint32_t ret;

    ret = scmi_drv_channel_verify(dev_id, channel);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if ((buf == NULL) || len == 0 || (len > MAILBOX_CHANNEL_SIZE)) {
        tloge("channel send data buf & len wrong!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = scmi_get_interrupt_status(dev_id, channel);
    if (ret != SCMI_CHANNEL_OCCUPIED) {
        tloge("scmi state is out-of-order, 0x%x.\n", ret);
        return TEE_ERROR_BAD_STATE; /* cannot return ret */
    }

    /* check channel state */
    ret = scmi_get_channel_state(dev_id, channel);
    if (ret == SCMI_BUSY) {
        tloge("channel is busy!\n");
        return TEE_ERROR_BAD_STATE; /* cannot return ret */
    }

    /* write data to mailbox */
    ret = scmi_write_mailbox(dev_id, channel, buf, len);

    /* send dooorbell */
    scmi_set_doorbell(dev_id, channel);

    return ret;
}

STATIC uint32_t scmi_check_task_and_get_data(uint32_t dev_id, uint32_t channel, uint8_t *buf, uint32_t len)
{
    volatile uint32_t loop = SCMI_CHECK_TIMEOUT;
    uint32_t ret;

    ret = scmi_drv_channel_verify(dev_id, channel);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if ((buf == NULL) || len == 0 || (len > MAILBOX_CHANNEL_SIZE)) {
        tloge("channel check failed!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = scmi_get_interrupt_status(dev_id, channel);
    if (ret != SCMI_CHANNEL_OCCUPIED) {
        tloge("scmi state is out-of-order, 0x%x.\n", ret);
        return TEE_ERROR_BAD_STATE; /* cannot return ret */
    }

    do {
        uint32_t val = g_scmi_interrupt_status[dev_id];

        val |= scmi_get_channel_notifyint(dev_id); // get doorbell notifyint
        if ((val & CHANNEL_TO_BIT(channel)) != 0) {
            g_scmi_interrupt_status[dev_id] = 0;
            /* get scmi data */
            return scmi_read_mailbox(dev_id, channel, buf, len);
        }
        SRE_SwMsleep(1);
        loop--;
    } while (loop > 0);

    return TEE_ERROR_BAD_STATE;
}

STATIC uint32_t scmi_paddr_to_vaddr(uint32_t dev_id, uint64_t vaddr)
{
    uint64_t vaddr_out = 0;
    uint32_t ret;

    if (vaddr == 0) {
        tloge("vaddr invalid.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = scmi_drv_channel_verify(dev_id, 0);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = drv_map_paddr_to_task(SHARE_DDR_ADDR_BASE + (dev_id * DEVICE_ADDR_OFFSET), SHARE_DDR_SIZE,
                                (UINT32 *)(uintptr_t)&vaddr_out, secure, non_cache); /* no sercue/no cache */
    if (ret != TEE_SUCCESS) {
        tloge("sre mmap failed, 0x%x.\n", ret);
        return ret;
    }

    *(uint64_t *)(uintptr_t)vaddr = vaddr_out;

    return TEE_SUCCESS;
}

int scmi_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t ret;
    uint32_t channel;
    uint32_t len;
    uint64_t buf;
    uint64_t v_addr;
    uint32_t dev_id;
    uint64_t *args = NULL;

    if ((params == NULL) || (params->args == 0)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    args = (uint64_t *)(uintptr_t)params->args;
    channel = args[ARRAY_INDEX0];

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SYSCALL_SCMI_CHANNEL_OPEN, permissions, HSM_GROUP_PERMISSION)
        dev_id = args[ARRAY_INDEX1];
        ret = scmi_channel_open(dev_id, channel);
        args[ARRAY_INDEX0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SCMI_CHANNEL_CLOSE, permissions, HSM_GROUP_PERMISSION)
        dev_id = args[ARRAY_INDEX1];
        ret = scmi_channel_close(dev_id, channel);
        args[ARRAY_INDEX0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SCMI_CHANNEL_SEND_DATA, permissions, HSM_GROUP_PERMISSION)
        buf = (((args[ARRAY_INDEX1]) << SHIFT_LEN_32) + args[ARRAY_INDEX2]);
        len = args[ARRAY_INDEX3];
        dev_id = args[ARRAY_INDEX4];
        ACCESS_CHECK_A64(buf, len);
        ACCESS_READ_RIGHT_CHECK(buf, len);
        ret = scmi_channel_send_data(dev_id, channel, (uint8_t *)(uintptr_t)buf, len);
        args[ARRAY_INDEX0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SCMI_CHANNEL_TASK_AND_GET_DATA, permissions, HSM_GROUP_PERMISSION)
        buf = (((args[ARRAY_INDEX1]) << SHIFT_LEN_32) + args[ARRAY_INDEX2]);
        len = args[ARRAY_INDEX3];
        dev_id = args[ARRAY_INDEX4];
        ACCESS_CHECK_A64(buf, len);
        ACCESS_WRITE_RIGHT_CHECK(buf, len);
        ret = scmi_check_task_and_get_data(dev_id, channel, (uint8_t *)(uintptr_t)buf, len);
        args[ARRAY_INDEX0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_SCMI_CHANNEL_PADDR2VADDR, permissions, HSM_GROUP_PERMISSION)
        v_addr = (uint64_t)(args[ARRAY_INDEX1]) + ((uint64_t)(args[ARRAY_INDEX2] << SHIFT_LEN_32));
        dev_id = args[ARRAY_INDEX3];
        ACCESS_CHECK_A64(v_addr, sizeof(uint64_t));
        ACCESS_WRITE_RIGHT_CHECK(v_addr, sizeof(uint64_t));
        ret = scmi_paddr_to_vaddr(dev_id, v_addr);
        args[ARRAY_INDEX0] = ret;
        SYSCALL_END
    default:
         return TEE_ERROR_NOT_SUPPORTED;
    }
    return 0;
}

DECLARE_TC_DRV(
    scmi_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    scmi_syscall,
    NULL,
    NULL
);
