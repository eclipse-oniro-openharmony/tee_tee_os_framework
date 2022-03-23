/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * foss@huawei.com
 *
 */
#include <sre_msg.h>
#include <drv_mem.h>
#include <bsp_param_cfg.h>
#include <bsp_modem_call.h>
#include "icc_core.h"
#include <bsp_shared_ddr.h>
#include <drv_mem.h>


struct icc_channel_base g_icc_channel_base;
extern struct icc_control g_icc_ctrl;


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

struct icc_init_info g_icc_init_info[] = {
    /* real_channel_id,   mode,                             fifo_size,              ipc_recv_irq_id, ipc_send_irq_id,
       func_size */
    {ICC_CHN_SEC_IFC, (ICC_NO_TASK << 2) | (ICC_IPC_SHARED), ICC_SEC_IFC_SIZE,  0, 0, IPC_SECOS_INT_SRC_CCPU_ICC_IFC,  IPC_CCPU_INT_SRC_SECOS_ICC_IFC,  20, "SEC_ICC_IFC"},
    { ICC_CHN_SEC_VSIM, (ICC_NO_TASK << 2) | (ICC_IPC_PRIVATE), ICC_SEC_VSIM_SIZE, 0, 0, IPC_SECOS_INT_SRC_CCPU_ICC_VSIM, IPC_CCPU_INT_SRC_SECOS_ICC_VSIM, 20, "SEC_ICC_VSIM" },        /*lint !e835 */
    { ICC_CHN_SEC_RFILE, (ICC_NO_TASK << 2) | (ICC_IPC_SHARED), ICC_SEC_RFILE_SIZE, 0, 0, IPC_SECOS_INT_SRC_CCPU_ICC_IFC, IPC_CCPU_INT_SRC_SECOS_ICC_IFC, 20, "SEC_ICC_RFILE" },         /*lint !e835 */
    { ICC_CHN_SEC_IFC_NR, (ICC_NO_TASK << 2) | (ICC_IPC_SHARED), ICC_SEC_IFC_NR_SIZE, 0, 0, IPC_SECOS_INT_SRC_NRCCPU_ICC_IFC, IPC_NRCCPU_INT_SRC_SECOS_ICC_IFC, 20, "SEC_ICC_IFC_NR" },    /*lint !e835 */
    { ICC_CHN_SEC_VSIM_NR, (ICC_NO_TASK << 2) | (ICC_IPC_PRIVATE), ICC_SEC_VSIM_NR_SIZE, 0, 0, IPC_SECOS_INT_SRC_NRCCPU_ICC_VSIM, IPC_NRCCPU_INT_SRC_SECOS_ICC_VSIM, 20, "SEC_ICC_VSIM_NR" }, /*lint !e835 */
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

/*lint -e528 -esym(528,*)*/
DECLARE_TC_DRV(icc_driver, 0, 0, 0, TC_DRV_MODULE_INIT, bsp_icc_init, NULL, NULL, NULL, NULL); /*lint -e528 +esym(528,*)*/
