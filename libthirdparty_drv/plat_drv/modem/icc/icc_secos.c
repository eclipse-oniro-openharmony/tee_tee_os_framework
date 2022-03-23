/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * foss@huawei.com
 *
 */
#include <sre_msg.h>
#include <mem_page_ops.h>
#include <drv_mem.h> // sre_mmap
#include <drv_pal.h> // task_caller
#include <drv_module.h>
#include <bsp_param_cfg.h>
#include <bsp_modem_call.h>
#include <bsp_shared_ddr.h>
#include "icc_core.h"

extern void gic_spi_notify();
#define UW_TASK_MAGIC 0xeadfa11e
#define UW_TASK_DEFAULT 0xffffffff
volatile int g_multicore_msg_switch = 1; /* default open */
struct icc_channel_base g_icc_channel_base;
extern struct icc_control g_icc_ctrl;

struct uw_task_id_info {
    unsigned int magic;
    unsigned int task_id;
};

/*lint -e754 +esym(754,*)*/
struct uw_task_id_info g_uw_task[ICC_CHN_ID_MAX - ICC_CHN_ACORE_CCORE_MIN] = {
    [0 ... ICC_CHN_ID_MAX - ICC_CHN_ACORE_CCORE_MIN - 1] = {UW_TASK_DEFAULT, UW_TASK_DEFAULT},
}; /*lint !e785 */

extern void irq_lock();
extern void irq_unlock();

/*lint -save -e438 */
void icc_restore_recv_channel_flag(struct icc_channel_fifo *channel_fifo)
{
    /* nothing to do */
    UNUSED(channel_fifo);
    return;
}
/*lint -restore +e438 */
int icc_channel_has_data(void)
{
    return ICC_OK;
}

void icc_shared_sem_init(void)
{
    (void)osl_sem_init(ICC_SEM_FULL, &g_icc_ctrl.shared_task_sem);
}

void icc_private_sem_init(osl_sem_id *private_sem)
{
    (void)osl_sem_init(ICC_SEM_FULL, private_sem);
}

/* 安全OS内不支持起任务，打桩 */
int icc_shared_task_init(void)
{
    return ICC_OK;
}

int bsp_icc_prepare(void)
{
    return icc_channel_has_data();
}

static int icc_multicore_msg_switch_on(unsigned int arg1, void *arg2, unsigned int arg3)
{
    UNUSED(arg1);
    UNUSED(arg2);
    UNUSED(arg3);
    g_multicore_msg_switch = 1;
    return ICC_OK;
}

static int icc_multicore_msg_switch_off(unsigned int arg1, void *arg2, unsigned int arg3)
{
    UNUSED(arg1);
    UNUSED(arg2);
    UNUSED(arg3);
    g_multicore_msg_switch = 0;
    return ICC_OK;
}

int icc_ccore_is_reseting(u32 cpuid)
{
    if ((g_multicore_msg_switch == 0) && (ICC_CPU_MODEM == cpuid)) {
        return 1;
    }

    return ICC_OK;
}

static int icc_channel_reset(unsigned int arg1, void *arg2, unsigned int arg3)
{
    struct icc_channel *channel = NULL;
    int i;

    UNUSED(arg1);
    UNUSED(arg2);
    UNUSED(arg3);

    for (i = ICC_CHN_ACORE_CCORE_MIN; i < ICC_CHN_ID_MAX; i++) {
        channel = g_icc_ctrl.channels[i];
        if (channel == NULL) {
            continue;
        }
        channel->fifo_send->read = 0;
        channel->fifo_send->write = 0;
    }
    return ICC_OK;
}

static int param_cfg_init(void)
{
    if (sre_mmap(DDR_SEC_SHARED_ADDR + SHM_OFFSET_SEC_ICC, SHM_SIZE_SEC_ICC, &g_icc_channel_base.addr, secure,
        non_cache)) {
        icc_print_error("map failed!base_addr = 0x%x, size = 0x%x\n", DDR_SEC_SHARED_ADDR + SHM_OFFSET_SEC_ICC,
            SHM_SIZE_SEC_ICC);
        return ICC_ERR;
    }

    g_icc_channel_base.size = SHM_SIZE_SEC_ICC;

    return ICC_OK;
}

int mdrv_icc_open_hook(unsigned int channel_id, void *ca_icc_attr_s, unsigned int len)
{
    UNUSED(channel_id);
    UNUSED(ca_icc_attr_s);
    UNUSED(len);
    return ICC_OK;
}

/*lint -restore +e715 +e732 */
int mdrv_icc_write_hook(unsigned int channel_id, void *buf, unsigned int buf_len)
{
    return bsp_icc_send(ICC_CPU_MODEM, channel_id, (unsigned char *)buf, buf_len);
}

int mdrv_icc_tryread_hook(unsigned int channel_id, void *buf, unsigned int buf_len)
{
    return bsp_icc_read(channel_id, (unsigned char *)buf, buf_len);
}

static int icc_call_register(void)
{
    int ret;

    ret = bsp_modem_call_register(FUNC_ICC_CHANNEL_RESET, icc_channel_reset);
    if (ret != 0) {
        icc_print_error("FUNC_ICC_CHANNEL_RESET register fail\n");
        return ICC_ERR;
    }

    ret = bsp_modem_call_register(FUNC_ICC_MSG_SWITCH_ON, icc_multicore_msg_switch_on);
    if (ret != 0) {
        icc_print_error("FUNC_ICC_MSG_SWITCH_ON register fail\n");
        return ICC_ERR;
    }

    ret = bsp_modem_call_register(FUNC_ICC_MSG_SWITCH_OFF, icc_multicore_msg_switch_off);
    if (ret != 0) {
        icc_print_error("FUNC_ICC_MSG_SWITCH_OFF register fail\n");
        return ICC_ERR;
    }

    ret = bsp_modem_call_register(FUNC_MDRV_ICC_OPEN, mdrv_icc_open_hook);
    if (ret != 0) {
        icc_print_error("FUNC_MDRV_ICC_OPEN register fail\n");
        return ICC_ERR;
    }

    ret = bsp_modem_call_register(FUNC_MDRV_ICC_WRITE, mdrv_icc_write_hook);
    if (ret != 0) {
        icc_print_error("FUNC_MDRV_ICC_WRITE register fail\n");
        return ICC_ERR;
    }

    ret = bsp_modem_call_register(FUNC_MDRV_ICC_TRYREAD, mdrv_icc_tryread_hook);
    if (ret != 0) {
        icc_print_error("FUNC_MDRV_ICC_TRYREAD register fail\n");
        return ICC_ERR;
    }

    return ICC_OK;
}

struct icc_init_info g_icc_init_info[] = {
    /* real_channel_id,   mode,                             fifo_size,              ipc_recv_irq_id, ipc_send_irq_id,
       func_size */
    {ICC_CHN_SEC_IFC, (ICC_NO_TASK << 2) | (ICC_IPC_SHARED), ICC_SEC_IFC_SIZE,  0, 0, IPC_SECOS_INT_SRC_CCPU_ICC_IFC,  IPC_CCPU_INT_SRC_SECOS_ICC_IFC,  20, "SEC_ICC_IFC"},
    { ICC_CHN_SEC_VSIM, (ICC_NO_TASK << 2) | (ICC_IPC_PRIVATE), ICC_SEC_VSIM_SIZE, 0, 0, IPC_SECOS_INT_SRC_CCPU_ICC_VSIM, IPC_CCPU_INT_SRC_SECOS_ICC_VSIM, 20, "SEC_ICC_VSIM" }, /*lint !e835 */
    { ICC_CHN_SEC_RFILE, (ICC_NO_TASK << 2) | (ICC_IPC_SHARED), ICC_SEC_RFILE_SIZE, 0, 0, IPC_SECOS_INT_SRC_CCPU_ICC_IFC, IPC_CCPU_INT_SRC_SECOS_ICC_IFC, 20, "SEC_ICC_RFILE" },  /*lint !e835 */
};

int icc_channels_init(void)
{
    unsigned int i;
    int ret;
    unsigned long last_channel_addr;
    unsigned long last_ch_fifo_info_size = 0; /* fifo头长度 */
    unsigned long last_ch_fifo_size = 0;      /* fifo本身长度，用来存放发送的数据包头+数据体 */
    char *icc_mem_addr_max;
    struct icc_init_info init_info = { 0 };
    struct icc_channel *channel = NULL;

    ret = param_cfg_init();
    if (ret != ICC_OK) {
        return ret;
    }

    ret = icc_call_register();
    if (ret != ICC_OK) {
        return ret;
    }

    last_channel_addr = (unsigned long)ICC_SDDR_S_START_ADDR_ON_THIS_CORE;
    icc_mem_addr_max = (char *)(uintptr_t)ICC_SDDR_S_ADDR_MAX;

    /* 有效的内存类型 */
    for (i = 0; i < sizeof(g_icc_init_info) / sizeof(g_icc_init_info[0]); i++) {
        init_info.name = g_icc_init_info[i].name; /* 通道名称 */
        init_info.real_channel_id = g_icc_init_info[i].real_channel_id;
        init_info.fifo_size = g_icc_init_info[i].fifo_size;
        init_info.mode = g_icc_init_info[i].mode;
        init_info.ipc_send_irq_id =
            g_icc_init_info[i].ipc_send_irq_id; /* 安全IPC 0-31号中断，modem侧对应32-63号中断 secos-->modem */
        init_info.ipc_recv_irq_id =
            g_icc_init_info[i].ipc_recv_irq_id; /* 安全IPC 0-31号中断，modem侧对应32-63号中断 modem-->secos */
        init_info.func_size = g_icc_init_info[i].func_size; /* 子通道最大值 */
        /* 本核上，本通道，先是接收后是发送 */
        init_info.recv_addr =
            (void *)(uintptr_t)(last_channel_addr + 2 * last_ch_fifo_info_size + 2 * last_ch_fifo_size);
        init_info.send_addr = (void *)(init_info.recv_addr + sizeof(struct icc_channel_fifo) + init_info.fifo_size);

        last_channel_addr = (uintptr_t)init_info.recv_addr;
        last_ch_fifo_info_size = sizeof(struct icc_channel_fifo);
        last_ch_fifo_size = init_info.fifo_size;

        if ((char *)(init_info.send_addr + sizeof(struct icc_channel_fifo) + init_info.fifo_size) > icc_mem_addr_max) {
            icc_print_error("addr too big\n");
            return ICC_INIT_ADDR_TOO_BIG;
        }

        icc_print_notice("========== channel cfg start============\n");
        icc_print_notice("ch_name %s\n", init_info.name);
        icc_print_notice("id 0x%x size 0x%x mode 0x%x\n", init_info.real_channel_id, init_info.fifo_size,
            init_info.mode);
        icc_print_notice("tx_ipc %d rx_ipc %d\n", init_info.ipc_send_irq_id, init_info.ipc_recv_irq_id);
        icc_print_notice("func_size 0x%x\n", init_info.func_size);
        icc_print_notice("fifo_send addr 0x%x fifo_recv addr 0x%x\n", init_info.send_addr, init_info.recv_addr);
        icc_print_notice("========== channel cfg end============\n");

        /* 初始化通道 */
        channel = icc_channel_init(&init_info, &ret);
        if ((channel == NULL) || (ICC_OK != ret)) {
            icc_print_error("chan setup err\n");
            return ICC_CHN_INIT_FAIL;
        }

        g_icc_ctrl.channels[init_info.real_channel_id] = channel;
    }
    return ICC_OK;
}

void icc_wakeup_flag_set(void)
{
    g_icc_ctrl.wake_up_flag = 1;
}

void icc_sleep_flag_set(void)
{
    g_icc_ctrl.sleep_flag = 1;
}

u32 bsp_icc_channel_status_get(u32 real_channel_id, u32 *channel_stat)
{
    struct icc_channel *channel = g_icc_ctrl.channels[real_channel_id];

    if (channel == NULL) {
        *channel_stat = ICC_CHN_CLOSED;
        return *channel_stat;
    }

    *channel_stat = channel->state;
    return *channel_stat;
}

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_BALTIMORE && TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_DENVER)
/*lint -e528 -esym(528,*)*/
DECLARE_TC_DRV(icc_driver, 0, 0, 0, TC_DRV_MODULE_INIT, bsp_icc_init, NULL, NULL, NULL, NULL);
/*lint -e528 +esym(528,*)*/
#endif
