/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Drivers for MSP core.
 * Author : w00371137
 * Create: 2019/11/11
 */

#include <mspc.h>
#include <mspc_ipc.h>
#include <mspc_errno.h>
#include <mspc_power.h>
#include <mspc_api.h>
#include <mspc_mem_layout.h>
#include <hmlog.h>
#include <drv_module.h>
#include <securec.h>
#include <sre_syscalls_id_ext.h>
#include <sre_access_control.h>
#include <register_ops.h>
#include <ipc_call.h>
#include <drv_pal.h>
#include <hmdrv_stub.h>
#include "drv_param_type.h"
#include <mspc_ipc_test.h>

#define MSPC_THIS_MODULE   MSPC_MODULE_TEEOS

#define SECFLASH_IS_ABSENCE_MAGIC         0x70eb2c2d
#define MSPC_RECOVERY_BEGIN               0xcdce296f
#define MSPC_RECOVERY_END                 0xbe950598
#define MSPC_RECOVERY_TIMEOUT             3 /* 3s for stability */

#define UNUSED(x) ((void)(x))

enum {
    MSPC_TEEOS_INVALID_CMD_ERR            = MSPC_ERRCODE(0x10),
    MSPC_TEEOS_GET_SHARED_DDR_ERR         = MSPC_ERRCODE(0x11),
    MSPC_TEEOS_NOT_RECOVERY_MODE          = MSPC_ERRCODE(0x12),
    MSPC_TEEOS_WRITELOCK_ACK_ERR          = MSPC_ERRCODE(0x13),
};

enum {
    MSPC_SECFLASH_STATUS_NULL           = 0x5A5A5A5A,
    MSPC_SECFLASH_STATUS_EXIST          = 0xC3C3C3C3,
    MSPC_SECFLASH_STATUS_ABSENCE        = 0x3C3C3C3C,
};

enum mspc_factory_cmd {
    MSPC_FAC_MODE_ENTER,
    MSPC_FAC_MODE_EXIT,
    MSPC_FAC_RECOVERY,
    MSPC_FAC_WRITE_LOCK,
};

enum secflash_info_recovery_e {
    SECFLASH_INFO_IN_RECOVERY = 0x55,
    SECFLASH_INFO_NO_RECOVERY = 0xAA,
};

union secflash_info_u {
    uint32_t value;
    struct {
        uint32_t device_status : 8;
        uint32_t interface : 8;
        uint32_t reset_gpio : 8;
        uint32_t is_recovery : 8;
    } bits;
};

struct mspc_factory_table {
    enum mspc_factory_cmd cmd;
    uint32_t (*factory_handle)(uint32_t params);
};

enum {
    MSPC_WRITELOCK_ACK_WAIT           = 0x5A5A5A5A,
    MSPC_WRITELOCK_ACK_OK             = 0xC3C3C3C3,
    MSPC_WRITELOCK_ACK_ERROR          = 0x3C3C3C3C,
};

#define MSPC_WRITELOCK_MAGIC_FLAG       0xa9929391
#define MSPC_SECFLASH_STATE_TIMEOUT     2  /* 2s */
#define MSPC_WRITELOCK_ACK_WAIT_TIME    5  /* 5s */

static volatile uint32_t g_mspc_writelock_flag;
static pthread_mutex_t g_mspc_writelock_mutex;

int32_t mspc_send_msg(struct mspc_cmd_info *cmd_data)
{
    int32_t ret;
    struct mspc_ipc_msg msg;

    if (!cmd_data) {
        tloge("%s:Invalid param!\n", __func__);
        return MSPC_ERRCODE(INVALID_PARAM);
    }

    (void)memset_s(&msg, sizeof(struct mspc_ipc_msg),
        0, sizeof(struct mspc_ipc_msg));

    /*
     * Copy cmd data to ipc msg, and will be copied to
     * ipc data registers later. From data1 begin to
     * store cmd data.
     */
    ret = memcpy_s((void *)&(msg.data[MSPC_IPC_DATA1]),
                   sizeof(msg.data) - sizeof(uint32_t),
                   (void *)cmd_data, sizeof(struct mspc_cmd_info));
    if (ret != EOK) {
        tloge("%s: memcpy_s err!\n", __func__);
        return MSPC_ERRCODE(LIBC_COPY_ERR);
    }

    msg.cmd_mix.cmd_obj  = OBJ_TEEOS;
    msg.cmd_mix.cmd_src  = OBJ_TEEOS;
    msg.cmd_mix.cmd      = CMD_SETTING;
    msg.cmd_mix.cmd_type = TYPE_MSPC_B;
    msg.mailbox_addr     = (uintptr_t)cmd_data->data;
    msg.mailbox_size     = cmd_data->block_size;

    return mspc_send_ipc(OBJ_MSPC, &msg, MSPC_ASYNC_MODE);
}

static int32_t mspc_writelock_ack(struct mspc_cmd_info *cmd_data)
{
    if (cmd_data->ack == MSPC_CMD_ACK_OK) {
        g_mspc_writelock_flag = MSPC_WRITELOCK_ACK_OK;
    } else {
        tloge("%s:ACK err %x, ret %x\n", __func__, cmd_data->ack, cmd_data->block_index);
        g_mspc_writelock_flag = MSPC_WRITELOCK_ACK_ERROR;
    }

    return MSPC_OK;
}

int32_t mspc_msg_process(struct mspc_ipc_msg *msg)
{
    int32_t ret = MSPC_TEEOS_INVALID_CMD_ERR;
    struct mspc_cmd_info *cmd_data = NULL;

    if (!msg) {
        tloge("%s:Invalid param!\n", __func__);
        return MSPC_ERRCODE(INVALID_PARAM);
    }

    cmd_data = (struct mspc_cmd_info *)(&msg->data[MSPC_IPC_DATA1]);
    cmd_data->data = (uint8_t *)msg->mailbox_addr;

    switch (cmd_data->cmd) {
    case MSPC_CMD_SEND_APDU:
        ret = mspc_send_apdu_process(cmd_data);
        break;
    case MSPC_CMD_RECV_APDU:
        ret = mspc_receive_apdu_process(cmd_data);
        break;
    case MSPC_CMD_INIT_APDU:
        ret = mspc_init_apdu_process(cmd_data);
        break;
    case MSPC_CMD_WRITELOCK:
        ret = mspc_writelock_ack(cmd_data);
        break;
    default:
        tloge("%s:Invalid cmd:%x\n", __func__, cmd_data->cmd);
        break;
    }
    return ret;
}

static int32_t mspc_init(void)
{
    int32_t ret;

    ret = mspc_power_init();
    if (ret != MSPC_OK) {
        tloge("MSPC init power module failed!\n");
        return ret;
    }

    ret = mspc_api_init();
    if (ret != MSPC_OK) {
        tloge("MSPC init api module failed!\n");
        return ret;
    }

    ret = mspc_ipc_init();
    if (ret != MSPC_OK) {
        tloge("MSPC init IPC failed!\n");
        return ret;
    }

    mspc_ipc_req_callback(OBJ_MSPC, CMD_SETTING, mspc_msg_process);
    return SRE_OK;
}

static int32_t mspc_suspend(void)
{
    int32_t ret;

    ret = mspc_power_suspend();
    if (ret != MSPC_OK) {
        tloge("MSPC suspend power failed!\n");
        return ret;
    }

    ret = SRE_OK;
    return ret;
}

static int32_t mspc_resume(void)
{
    int32_t ret;

    ret = mspc_ipc_resume();
    if (ret != MSPC_OK) {
        tloge("MSPC resume ipc failed!\n");
        return ret;
    }

    ret = SRE_OK;
    return ret;
}

static uint32_t mspc_check_secflash(uint32_t *status)
{
    int32_t ret;
    uint32_t base_addr, status_addr;

    if (!status) {
        tloge("%s:Invalid param!\n", __func__);
        return MSPC_ERRCODE(INVALID_PARAM);
    }

    base_addr = mspc_get_shared_ddr();
    if (base_addr == 0) {
        tloge("%s:get shared ddr failed!\n", __func__);
        return MSPC_TEEOS_GET_SHARED_DDR_ERR;
    }

    status_addr = base_addr + MSPC_SECFLASH_STATUS_OFFSET;
    write32(status_addr, MSPC_SECFLASH_STATUS_NULL);

    ret = __ipc_smc_switch(TEE_MSPC_CHECK_SECFLASH);
    if (ret != MSPC_OK) {
        tloge("%s:send smc failed [%x]!\n", __func__, (uint32_t)ret);
        return ret;
    }

    *status = read32(status_addr);
    tloge("%s %x\n", __func__, *status);
    return SRE_OK;
}

static uint32_t mspc_recovery(uint32_t flags)
{
    int32_t ret;
    int32_t ret_trace;
    uint32_t base_addr, status_addr;
    union secflash_info_u info;

    UNUSED(flags);
    base_addr = mspc_get_shared_ddr();
    if (base_addr == 0) {
        tloge("%s:get shared ddr failed!\n", __func__);
        return MSPC_TEEOS_GET_SHARED_DDR_ERR;
    }

    info.value = read32(base_addr + MSPC_SECFLASH_INFO_OFFSET);
    if (info.bits.is_recovery != SECFLASH_INFO_IN_RECOVERY) {
        tloge("%s:not in recovery mode!\n", __func__);
        return MSPC_TEEOS_NOT_RECOVERY_MODE;
    }
    status_addr = base_addr + MSPC_RECOVERY_STATUS_OFFSET;
    write32(status_addr, MSPC_RECOVERY_BEGIN);

    ret = mspc_power_on(MSPC_FACTORY_VOTE_ID);
    if (ret != MSPC_OK) {
        tloge("%s: power on mspc failed: %x\n", __func__, (uint32_t)ret);
        write32(status_addr, MSPC_RECOVERY_END);
        return ret;
    }
    ret = mspc_wait_native_ready(MSPC_RECOVERY_TIMEOUT);
    if (ret != MSPC_OK) {
        tloge("%s: wait native ready err: %x\n", __func__, (uint32_t)ret);
        ret_trace = mspc_power_off(MSPC_FACTORY_VOTE_ID);
        tloge("%s: power off %x\n", (uint32_t)ret_trace);
        write32(status_addr, MSPC_RECOVERY_END);
        return ret;
    }

    ret = mspc_power_off(MSPC_FACTORY_VOTE_ID);
    if (ret != MSPC_OK)
        tloge("%s: power off fail %x\n", (uint32_t)ret);
    write32(status_addr, MSPC_RECOVERY_END);
    return ret;
}

static int32_t mspc_wait_writelock_ack(void)
{
    struct timespec start_ts = {0};
    struct timespec end_ts = {0};

    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    while (g_mspc_writelock_flag == MSPC_WRITELOCK_ACK_WAIT) {
        clock_gettime(CLOCK_MONOTONIC, &end_ts);
        if (end_ts.tv_sec < start_ts.tv_sec ||
            (uint32_t)(end_ts.tv_sec - start_ts.tv_sec) > MSPC_WRITELOCK_ACK_WAIT_TIME) {
            tloge("%s:timeout!end:%d, start:%d\n",
                  __func__, end_ts.tv_sec, start_ts.tv_sec);
            return MSPC_ERRCODE(TIMEOUT_ERR);
        }
    }

    if (g_mspc_writelock_flag == MSPC_WRITELOCK_ACK_OK)
        return MSPC_OK;
    return MSPC_TEEOS_WRITELOCK_ACK_ERR;
}

static int32_t mspc_run_for_secflash_writelock(uint32_t is_set_op)
{
    int32_t ret, ret1;
    uint32_t base_addr, status_addr;
    struct mspc_cmd_info cmd = { 0 };

    base_addr = mspc_get_shared_ddr();
    if (base_addr == 0) {
        tloge("%s:get shared ddr failed!\n", __func__);
        return MSPC_TEEOS_GET_SHARED_DDR_ERR;
    }

    /* set magic flag before poweron */
    status_addr = base_addr + MSPC_WRITELOCK_STATUS_OFFSET;
    write32(status_addr, MSPC_WRITELOCK_MAGIC_FLAG);
    ret = mspc_power_on(MSPC_FACTORY_VOTE_ID);
    if (ret != MSPC_OK) {
        tloge("%s: power on mspc failed: %x\n", __func__, (uint32_t)ret);
        write32(status_addr, 0);
        return ret;
    }

    ret = mspc_wait_state(MSPC_STATE_SECFLASH, MSPC_SECFLASH_STATE_TIMEOUT);
    if (ret != MSPC_OK) {
        tloge("%s: wait secflash ready err: %x\n", __func__, (uint32_t)ret);
        goto exit;
    }

    /* send ipc to mspc for writelock */
    g_mspc_writelock_flag = MSPC_WRITELOCK_ACK_WAIT;
    cmd.cmd = MSPC_CMD_WRITELOCK;
    cmd.block_index = is_set_op;
    ret = mspc_send_msg(&cmd);
    if (ret != MSPC_OK) {
        tloge("%s: send msg err: %x\n", __func__, (uint32_t)ret);
        goto exit;
    }

    ret = mspc_wait_writelock_ack();
exit:
    write32(status_addr, 0);
    ret1 = mspc_power_off(MSPC_FACTORY_VOTE_ID);
    if (ret1 != MSPC_OK)
        tloge("%s: poweroff err: %x\n", __func__, (uint32_t)ret1);

    return (ret == MSPC_OK) ? ret1 : ret;
}

static uint32_t mspc_secflash_writelock(uint32_t is_set_op)
{
    int32_t ret;

    (void)pthread_mutex_lock(&g_mspc_writelock_mutex);

    ret = mspc_run_for_secflash_writelock(is_set_op);

    (void)pthread_mutex_unlock(&g_mspc_writelock_mutex);
    return (uint32_t)ret;
}

static const struct mspc_factory_table g_mspc_factory_table[] = {
    { MSPC_FAC_MODE_ENTER, mspc_power_fac_mode_entry },
    { MSPC_FAC_MODE_EXIT,  mspc_power_fac_mode_exit },
    { MSPC_FAC_RECOVERY,   mspc_recovery },
    { MSPC_FAC_WRITE_LOCK, mspc_secflash_writelock }
};

static uint32_t mspc_factory_cmd_handle(uint32_t cmd, uint32_t params)
{
    uint32_t i;
    uint32_t len = ARRAY_SIZE(g_mspc_factory_table);

    for (i = 0; i < len; i++) {
        if (g_mspc_factory_table[i].cmd == cmd && g_mspc_factory_table[i].factory_handle)
            return g_mspc_factory_table[i].factory_handle(params);
    }
    tloge("%s invalid cmd\n", __func__);
    return MSPC_TEEOS_INVALID_CMD_ERR;
}

int32_t mspc_syscall(int32_t swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t uw_ret;

    if (!params || !params->args) {
        tloge("%s invalid input\n", __func__);
        return -1;
    }
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_MSPC_CHECK_SECFLASH,
                           permissions, MSPC_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], sizeof(uint32_t));
        ACCESS_WRITE_RIGHT_CHECK(args[0], sizeof(uint32_t));

        uw_ret = mspc_check_secflash((uint32_t *)(uintptr_t)args[0]);
        args[0] = uw_ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_MSPC_FACOTRY_CMD,
                           permissions, MSPC_GROUP_PERMISSION)

        uw_ret = mspc_factory_cmd_handle((uint32_t)args[0], (uint32_t)args[1]);
        args[0] = uw_ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_MSPC_POWER_ON,
                           permissions, MSPC_GROUP_PERMISSION)

        uw_ret = mspc_power_on((uint32_t)args[0]);
        args[0] = uw_ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_MSPC_POWER_OFF,
                           permissions, MSPC_GROUP_PERMISSION)

        uw_ret = mspc_power_off((uint32_t)args[0]);
        args[0] = uw_ret;
        SYSCALL_END
#ifdef CONFIG_HISI_MSPC_IPC_TEST
        /* 0 - 5: number of args */
        SYSCALL_PERMISSION(SW_SYSCALL_MSPC_IPC_TEST,
                            permissions, MSPC_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], args[1]);
        ACCESS_WRITE_RIGHT_CHECK(args[0], args[1]);
        uw_ret = mspc_ipc_test((struct mspc_ipc_test_msg *)(uintptr_t)args[0]);
        args[0] = uw_ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_MSPC_DDR_READ,
                           permissions, MSPC_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[2], args[3]);
        ACCESS_WRITE_RIGHT_CHECK(args[2], args[3]);
        ACCESS_CHECK_A64(args[4], args[5]);
        ACCESS_WRITE_RIGHT_CHECK(args[4], args[5]);
        uw_ret = mspc_ddr_read((uint32_t)args[0], (uint32_t)args[1],
            (uint8_t *)(uintptr_t)args[2], (uint32_t *)(uintptr_t)args[4]);
        args[0] = uw_ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_MSPC_DDR_WRITE,
                           permissions, MSPC_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[0], args[1]);
        ACCESS_WRITE_RIGHT_CHECK(args[0], args[1]);
        uw_ret = mspc_ddr_write((uint8_t *)(uintptr_t)args[0], (uint32_t)args[1], (uint32_t)args[2]);
        args[0] = uw_ret;
        SYSCALL_END
#endif
        default :
            return OS_ERROR;
    }
    return SRE_OK;
}

DECLARE_TC_DRV(
    mspc_driver,        /* name */
    0,                  /* reserved1 */
    0,                  /* reserved2 */
    0,                  /* reserved3 */
    TC_DRV_MODULE_INIT, /* priority */
    mspc_init,          /* init */
    NULL,               /* handle */
    mspc_syscall,       /* syscall */
    mspc_suspend,       /* suspend */
    mspc_resume         /* resume */
);
