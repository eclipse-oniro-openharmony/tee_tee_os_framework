/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Drivers for msp core IPC.
 * Create: 2019/11/20
 */

#include <mspc_ipc.h>
#include <mspc.h>
#include <mspc_errno.h>
#include <mspc_power.h>
#include <mspc_mem_layout.h>
#include <sre_hwi.h>
#include <secure_gic_common.h>
#include <tee_log.h>
#include <hmlog.h>
#include <pthread.h>
#include <securec.h>
#include <ipc_call.h> /* __ipc_smc_switch */
#include <soc_acpu_baseaddr_interface.h>
#include <soc_gic600_interface.h>
#include <soc_ipc_interface.h>
#include <register_ops.h>

#define MSPC_THIS_MODULE            MSPC_MODULE_IPC

#define MAX_IPC_CALLBACK_NUM        4 /* 4 callback. */
#define REG_SIZE                    4 /* 4 Bytes, 32 bits. */
#define WORD_LEN                    4

#define MSPC_MAILBOX_SRAM_BLOCK     32
#define MSPC_MAILBOX_BLOCK_SIZE     512

/* 200ms timeout while waiting idle */
#define IPC_WAIT_IDLE_TIMEOUT_US    200000

#define REG_UNLOCK_KEY              0x1ACCE551

#define MSPC_TEE_SOURCE             4
#define MSPC_SOURCE                 7

/* IPC STATUS DEFINE */
#define MBOX_STATE_MASK             0xF0
#define MBOX_IDLE_STATE             0x10
#define MBOX_SRC_STATE              0x20
#define MBOX_DST_STATE              0x40
#define MBOX_ACK_STATE              0x80

#define MBOX_MODE_MASK              0x03
#define MSPC_MBOX_AUTOACK           0x01
#define MSPC_MBOX_MANUACK           0x00

#define IPC_SET_TIMEOUT_US          20

#define MSPC_IRQ_PRIO               0

enum mspc_block_id {
    MBOX_MSPC_ATF    = 3,    /* SRAM FLAG which is used for MSPC->ATF IPC */
    MBOX_MSPC_MODEM  = 7,    /* SRAM FLAG which is used for MODEM<->MSPC IPC */
    MBOX_MSPC_HIFI   = 8,    /* SRAM FLAG which is used for HIFI <->MSPC IPC */
    MBOX_MSPC_LPMCU  = 9,    /* SRAM FLAG which is used for LPMCU<->MSPC IPC */
    MBOX_ATF_MSPC    = 10,   /* SRAM FLAG which is used for ATF ->MSPC IPC */
    MBOX_MSPC_TEE    = 11,   /* SRAM FLAG which is used for TEE <->MSPC IPC */
    MBOX_MSPC_IOM7   = 12,   /* SRAM FLAG which is used for IOM7<->MSPC IPC */
    MBOX_MSPC_ISP    = 13,   /* SRAM FLAG which is used for ISP<->MSPC IPC */
    MAX_MBOX_FLAG    = 0xFF, /* MAX FLAG */
};

enum {
    MSPC_IPC_CALLBACK_NUM_ERR          = MSPC_ERRCODE(0x10),
    MSPC_IPC_CALLBACK_REGISTERD_ERR    = MSPC_ERRCODE(0x11),
    MSPC_IPC_POWER_STATE_ERR           = MSPC_ERRCODE(0x12),
    MSPC_IPC_MBX_INFO_ERR              = MSPC_ERRCODE(0x13),
    MSPC_IPC_IRQ_ERR                   = MSPC_ERRCODE(0x14),
    MSPC_IPC_MUTEX_ERR                 = MSPC_ERRCODE(0x15),
};

struct ipc_cb_st {
    uint32_t obj;
    uint32_t cmd;
    int32_t (*ipc_msg_cb)(struct mspc_ipc_msg *);
};

static struct ipc_cb_st g_ipc_msg_ops[MAX_IPC_CALLBACK_NUM];
static int32_t g_ipc_cb_current_num;
static pthread_mutex_t g_ipc_mutex;

static const uint32_t g_mspc_ipc_irq[] = {
    IPC_ATF_ACK_MBXFIQ,
    IPC_TEE_ACK_MBXFIQ,
    IPC_ATF_MBXFIQ,
    IPC_TEE_MBXFIQ,
};

/* 本接口为调用中软提供的库,中软未提供头文件.已备案 */
extern int __ipc_smc_switch(unsigned int irq);

int32_t mspc_ipc_req_callback(uint32_t obj, uint32_t cmd,
                              int32_t (*func)(struct mspc_ipc_msg *))
{
    int32_t i;

    if (!func || obj >= MAX_CMD_OBJ || cmd >= MAX_CMD_MODE) {
        tloge("mspc error: Invalid para! obj:%u, cmd:%u\n", obj, cmd);
        return MSPC_ERRCODE(INVALID_PARAM);
    }
    if (g_ipc_cb_current_num >= MAX_IPC_CALLBACK_NUM) {
        tloge("mspc error: Func number err!\n");
        return MSPC_IPC_CALLBACK_NUM_ERR;
    }

    for (i = 0; i < g_ipc_cb_current_num; i++) {
        if (g_ipc_msg_ops[i].obj == obj &&
            g_ipc_msg_ops[i].cmd == cmd &&
            g_ipc_msg_ops[i].ipc_msg_cb) {
            tloge("mspc error: The callback has been registered.\n");
            return MSPC_IPC_CALLBACK_REGISTERD_ERR;
        }
    }

    g_ipc_msg_ops[g_ipc_cb_current_num].obj = obj;
    g_ipc_msg_ops[g_ipc_cb_current_num].cmd = cmd;
    g_ipc_msg_ops[g_ipc_cb_current_num].ipc_msg_cb = func;
    g_ipc_cb_current_num++;

    return MSPC_OK;
}

/*
 * @brief      : mspc_lock_accessing : When TEEOS access msp ipc registers,
 *       msp core need keep powering on. Otherwise, it will make
 *       a panic. Here we set a flag to system back register which
 *       can prevent lpmcu to power off msp core. Also we need check
 *       the msp power state to make sure msp core is really on.
 *
 * @return     : MSPC_OK: successful, MSPC_POWER_STATE_ERR: failed.
 */
static int32_t mspc_lock_accessing(void)
{
    /*
     * Make sure that msp core is powered on before accessing mailbox.
     * Use mspc_set_access_flag() to set a flag which can prevent
     * powering off mspc in lpmcu.
     */
    mspc_set_access_flag();

    if (mspc_get_power_status() == MSPC_STATE_POWER_DOWN) {
        mspc_clear_access_flag();
        return MSPC_IPC_POWER_STATE_ERR;
    }
    return MSPC_OK;
}

/*
 * @brief      : mspc_unlock_accessing : After accessing ipc registers, you
 *       need call this function to clear the accessing flag, so that
 *       lpmcu can power off msp core.
 */
static void mspc_unlock_accessing(void)
{
    mspc_clear_access_flag();
}

int32_t mspc_ipc_get_mbx_ram(uint32_t mbx_id, uint32_t *size, uint32_t *addr)
{
    uint32_t i, val;
    int32_t ret;
    uint32_t mbx_num = 0;
    uint32_t dst = 0;
    enum mspc_block_id block = MBOX_MSPC_TEE;

    if (!size || !addr) {
        tloge("%s:NULL pointer!\n", __func__);
        return MSPC_ERRCODE(INVALID_PARAM);
    }

    /* There are only two ipc channels between ATF with msp core. */
    if (mbx_id != IPC_MSPC_FASTMBOX && mbx_id != IPC_TEE_FASTMBOX) {
        tloge("mspc error: Invalid mbx id:%d\n", mbx_id);
        return MSPC_ERRCODE(INVALID_PARAM);
    }

    ret = mspc_lock_accessing();
    if (ret != MSPC_OK) {
        tloge("%s:lock mspc accessing failed!\n", __func__);
        return ret;
    }

    for (i = 0; i < MSPC_MAILBOX_SRAM_BLOCK; i++) {
        val = *(uint8_t *)(uintptr_t)(MSPC_MBXRAM_TABLE_PHYMEM_ADDR + i);
        if (block == val) {
            mbx_num++;
            /* i maximum is 32, BLOCK_SIZE is 512. Cann't overflow! */
            if (dst == 0)
                dst = (uint32_t)(MSPC_MBXRAM_PHYMEM_ADDR +
                        i * MSPC_MAILBOX_BLOCK_SIZE);
        }
    }
    mspc_unlock_accessing();

    /* mbx_num max is 32, BLOCK_SIZE is 512. Cann't overflow! */
    *size = mbx_num * MSPC_MAILBOX_BLOCK_SIZE;
    *addr = dst;

    return MSPC_OK;
}

static void mspc_ipc_dump(uint32_t mbx)
{
    uint32_t base = SOC_ACPU_HISEE_IPC_BASE_ADDR;
    uint32_t i;

    tloge("Mbx%u\n", mbx);
    tloge("SRC%x\n", read32(SOC_IPC_MBX_SOURCE_ADDR(base, mbx)));
    tloge("MODE%x\n", read32(SOC_IPC_MBX_MODE_ADDR(base, mbx)));
    tloge("ICLR%x\n", read32(SOC_IPC_MBX_ICLR_ADDR(base, mbx)));
    for (i = 0; i < MAX_MAIL_SIZE; i++)
        tloge("[DATA%u]:%x\n", i,
              read32(SOC_IPC_MBX_DATA0_ADDR(base, mbx) + sizeof(uint32_t) * i));
}

static int32_t mspc_ipc_wait_idle(const struct mspc_ipc_msg *cfg)
{
    uint8_t mailbox;
    uint32_t val;
    bool b_released = false;
    uint32_t ipc_base = SOC_ACPU_HISEE_IPC_BASE_ADDR;
    uint32_t time_out = IPC_WAIT_IDLE_TIMEOUT_US;
    const uint8_t src_bit = BIT(MSPC_TEE_SOURCE);

    mailbox  = cfg->mailbox_id;

    /* wait mailbox idle */
    while (time_out != 0) {
        val = read32(SOC_IPC_MBX_MODE_ADDR(ipc_base, mailbox));
        if ((val & MBOX_STATE_MASK) == MBOX_IDLE_STATE)
            break;
        if ((val & MBOX_STATE_MASK) == MBOX_ACK_STATE && !b_released) {
            /* Clear irq */
            write32(SOC_IPC_MBX_ICLR_ADDR(ipc_base, mailbox), src_bit);
            /* Release mailbox */
            write32(SOC_IPC_MBX_SOURCE_ADDR(ipc_base, mailbox), src_bit);
        }

        time_out--;
    }

    if (time_out == 0) {
        tloge("%s: wait idle timeout!\n", __func__);
        mspc_ipc_dump(mailbox);
        return MSPC_ERRCODE(TIMEOUT_ERR);
    }

    return MSPC_OK;
}

static int32_t mspc_ipc_request_mbx(const struct mspc_ipc_msg *cfg)
{
    int32_t ret;
    uint8_t mailbox;
    uint32_t timeout, val, source;
    uint32_t ipc_base = SOC_ACPU_HISEE_IPC_BASE_ADDR;

    mailbox  = cfg->mailbox_id;
    source   = cfg->src_id;

    write32(SOC_IPC_LOCK_ADDR(ipc_base), REG_UNLOCK_KEY);

    ret = mspc_ipc_wait_idle(cfg);
    if (ret != MSPC_OK)
        return ret;

    /* Request to use mailbox */
    timeout = IPC_SET_TIMEOUT_US;
    do {
        if (read32(SOC_IPC_MBX_SOURCE_ADDR(ipc_base, mailbox)) == 0)
            write32(SOC_IPC_MBX_SOURCE_ADDR(ipc_base, mailbox), source);
        val = read32(SOC_IPC_MBX_SOURCE_ADDR(ipc_base, mailbox));
        if (val == source)
            break;
        /* wait 1us for ipc status change */
        timeout--;
    } while (timeout != 0);

    if (timeout == 0) {
        tloge("%s: request mbx timeout!\n", __func__);
        mspc_ipc_dump(mailbox);
        return MSPC_ERRCODE(TIMEOUT_ERR);
    }

    return MSPC_OK;
}

void mspc_mailbox_data_copy(uint8_t *dst, uint8_t *src, uint32_t size)
{
    uint32_t i;
    uint32_t word_size = size / WORD_LEN;
    uint32_t byte_size = size % WORD_LEN;
    uint32_t *word_dst = (uint32_t *)dst;
    uint32_t *word_src = (uint32_t *)src;
    uint8_t *byte_dst = dst + word_size * WORD_LEN;
    uint8_t *byte_src = src + word_size * WORD_LEN;

    if (!dst || !src || size == 0) {
        tloge("%s:Invalid param,size is %x\n", __func__, size);
        return;
    }
    for (i = 0; i < word_size; i++)
        *word_dst++ = *word_src++;

    for (i = 0; i < byte_size; i++)
        *byte_dst++ = *byte_src++;
}

static int32_t mspc_ipc_copy_data(const struct mspc_ipc_msg *cfg)
{
    int32_t ret;
    uint32_t size = 0;
    uint32_t addr = 0;

    if (cfg->mailbox_size == 0 || cfg->mailbox_addr == 0)
        return MSPC_OK;

    /* Get mailbox sram addr based on mailbox id */
    ret = mspc_ipc_get_mbx_ram(cfg->mailbox_id, &size, &addr);
    if (ret != MSPC_OK) {
        tloge("%s:get mailbox ram info failed!\n", __func__);
        return ret;
    }
    if (cfg->mailbox_size > size || addr == 0) {
        tloge("%s:Invalid mailbox ram info!%x,%x\n", __func__, size, addr);
        return MSPC_IPC_MBX_INFO_ERR;
    }

    if (cfg->mailbox_addr != addr)
        mspc_mailbox_data_copy((uint8_t *)(uintptr_t)addr,
                               (uint8_t *)cfg->mailbox_addr,
                               cfg->mailbox_size);

    return MSPC_OK;
}

static int32_t mspc_ipc_send_msg(const struct mspc_ipc_msg *cfg)
{
    int32_t ret;
    uint32_t addr, source;
    uint8_t i, mailbox;
    uint32_t ipc_base = SOC_ACPU_HISEE_IPC_BASE_ADDR;

    mailbox  = cfg->mailbox_id;
    source   = cfg->src_id;

    ret = mspc_lock_accessing();
    if (ret != MSPC_OK) {
        tloge("%s:lock mspc accessing failed!\n", __func__);
        return ret;
    }

    /* request mbx */
    ret = mspc_ipc_request_mbx(cfg);
    if (ret != MSPC_OK) {
        tloge("%s:Request mbx fail!\n", __func__);
        goto exit;
    }

    /* set irq mask */
    write32(SOC_IPC_MBX_IMASK_ADDR(ipc_base, mailbox),
            ~(source | cfg->dest_id));

    /* set mailbox workmode */
    write32(SOC_IPC_MBX_MODE_ADDR(ipc_base, mailbox),
            (cfg->mode & MBOX_MODE_MASK));

    /* set mailbox data */
    for (i = 0; i < MAX_MAIL_SIZE; i++) {
        addr = SOC_IPC_MBX_DATA0_ADDR(ipc_base, mailbox) + i * sizeof(uint32_t);
        write32(addr, cfg->data[i]);
    }

    ret = mspc_ipc_copy_data(cfg);
    if (ret != MSPC_OK) {
        tloge("%s:copy data failed!\n", __func__);
        goto exit;
    }

    /* send msg */
    write32(SOC_IPC_MBX_SEND_ADDR(ipc_base, mailbox), source);
exit:
    mspc_unlock_accessing();

    return ret;
}

/* This intterface is just send ipc to msp core. */
int32_t mspc_send_ipc(uint32_t obj, struct mspc_ipc_msg *msg, uint32_t mode)
{
    int32_t ret;

    if (!msg) {
        tloge("%s:NULL pointer!\n", __func__);
        return MSPC_ERRCODE(INVALID_PARAM);
    }

    if (mode == MSPC_SYNC_MODE) {
        msg->mode = MSPC_MBOX_MANUACK;
    } else if (mode == MSPC_ASYNC_MODE) {
        msg->mode = MSPC_MBOX_AUTOACK;
    } else {
        tloge("%s:Invalid mode:%x!\n", __func__, mode);
        return MSPC_ERRCODE(INVALID_PARAM);
    }

    /* For msp core ipc, ATF just can send to MSP Core. */
    if (obj != OBJ_MSPC) {
        tloge("%s:Invalid obj:%x!\n", __func__, obj);
        return MSPC_ERRCODE(INVALID_PARAM);
    }

    msg->dest_id    = BIT(MSPC_SOURCE);
    msg->mailbox_id = IPC_MSPC_FASTMBOX;
    msg->ipc_base   = SOC_ACPU_HISEE_IPC_BASE_ADDR;
    msg->src_id = BIT(MSPC_TEE_SOURCE);

    (void)pthread_mutex_lock(&g_ipc_mutex);
    ret = mspc_ipc_send_msg(msg);
    if (ret != MSPC_OK)
        tloge("%s:send ipc message failed!\n", __func__);

    (void)pthread_mutex_unlock(&g_ipc_mutex);

    return ret;
}

static int32_t mspc_ipc_recv_msg(uint8_t mbx, struct mspc_ipc_msg *cfg)
{
    uint32_t i, addr;
    uint32_t mbx_addr = 0;
    uint32_t mbx_size = 0;
    uint32_t phymem_end;
    int32_t ret;
    uint32_t ipc_base = SOC_ACPU_HISEE_IPC_BASE_ADDR;

    /* Read data from ipc data registers. */
    for (i = 0; i < MAX_MAIL_SIZE; i++) {
        addr = SOC_IPC_MBX_DATA0_ADDR(ipc_base, mbx) + i * REG_SIZE;
        cfg->data[i] = read32(addr);
    }

    /* Get mailbox sram addr based on mailbox id */
    ret = mspc_ipc_get_mbx_ram(mbx, &mbx_size, &mbx_addr);
    if (ret != MSPC_OK) {
        tloge("%s:get mailbox ram info failed!\n", __func__);
        goto exit;
    }
    if (mbx_size == 0 || mbx_addr == 0) {
        tloge("%s:no msp core mailbox ram!\n", __func__);
        ret = MSPC_IPC_MBX_INFO_ERR;
        goto exit;
    }

    phymem_end = MSPC_MBXRAM_PHYMEM_ADDR + MSPC_MBXRAM_PHYMEM_SIZE;
    if (mbx_addr < MSPC_MBXRAM_PHYMEM_ADDR ||
        mbx_addr >= phymem_end ||
        mbx_size > MSPC_MBXRAM_PHYMEM_SIZE ||
        mbx_addr + mbx_size < mbx_addr ||
        mbx_addr + mbx_size > phymem_end) {
        tloge("%s:Get mbx ram failed, addr:0x%x, size:%d\n",
              __func__, mbx_addr, mbx_size);
        ret = MSPC_IPC_MBX_INFO_ERR;
        goto exit;
    }
    cfg->mailbox_addr = mbx_addr;
    cfg->mailbox_size = mbx_size;
    /* Write back zero, if read success */
    write32(SOC_IPC_MBX_DATA1_ADDR(ipc_base, mbx), 0);

exit:
    /* Clear irq */
    write32(SOC_IPC_MBX_ICLR_ADDR(ipc_base, mbx), BIT(MSPC_TEE_SOURCE));
    return ret;
}

static void mspc_receive_ipc(uint8_t mbx)
{
    int32_t ret, i;
    uint8_t obj, cmd;
    struct mspc_ipc_msg msg;

    (void)memset_s(&msg, sizeof(struct mspc_ipc_msg),
        0, sizeof(struct mspc_ipc_msg));

    /* read msg from hardware */
    ret = mspc_ipc_recv_msg(mbx, &msg);
    if (ret != MSPC_OK) {
        tloge("%s:receive msg err!\n", __func__);
        return;
    }

    /* Handle messages. */
    obj = msg.cmd_mix.cmd_obj;
    cmd = msg.cmd_mix.cmd;

    if (obj >= MAX_CMD_OBJ || cmd >= MAX_CMD_MODE) {
        tloge("%s:Invalid param! obj:0x%x, cmd:0x%x\n",
              __func__, obj, cmd);
        return;
    }

    ret = MSPC_ERROR;
    for (i = 0; i < g_ipc_cb_current_num; i++) {
        if (g_ipc_msg_ops[i].obj == obj &&
            g_ipc_msg_ops[i].cmd == cmd &&
            g_ipc_msg_ops[i].ipc_msg_cb) {
            ret = g_ipc_msg_ops[i].ipc_msg_cb(&msg);
            break;
        }
    }

    if (ret != MSPC_OK)
        tloge("%s:handle msg failed! i:%d, obj:%u, cmd:%u, ret:%d\n",
              __func__, i, obj, cmd, ret);
}

static void mspc_ipc_recv_ack(uint8_t mbx)
{
    uint32_t val;
    uint32_t base = SOC_ACPU_HISEE_IPC_BASE_ADDR;
    const uint8_t src_bit = BIT(MSPC_TEE_SOURCE);

    val = read32(SOC_IPC_MBX_MODE_ADDR(base, mbx));
    if ((val & MBOX_STATE_MASK) == MBOX_ACK_STATE) {
        /* Clear irq */
        write32(SOC_IPC_MBX_ICLR_ADDR(base, mbx), src_bit);
        /* Release mailbox */
        write32(SOC_IPC_MBX_SOURCE_ADDR(base, mbx), src_bit);
    } else {
        /* Ack has been cleared by ipc_send_msg() when checking idle. */
        tloge("MSPCIpcAckHasBennCleared\n");
    }
}

static bool mspc_ipc_is_ack(uint8_t mbx)
{
    uint32_t status, val;
    uint32_t base = SOC_ACPU_HISEE_IPC_BASE_ADDR;
    const uint8_t src_bit = MSPC_TEE_SOURCE;

    status = read32(SOC_IPC_CPU_IMST_ADDR(base, src_bit));
    if ((status & BIT(mbx)) != 0) {
        val = read32(SOC_IPC_MBX_SOURCE_ADDR(base, mbx));
        return val == BIT(src_bit);
    }
    return false;
}

/**
 * @brief      : mspc_ipc_irq_handler : Handle MSP core ipc interrupt.
 *
 * @param[in]  : irq : interrupt number.
 */
void mspc_ipc_irq_handler(uint32_t irq)
{
    int32_t ret;

    /* Transmit to ATF. */
    if (irq == IPC_ATF_MBXFIQ || irq == IPC_ATF_ACK_MBXFIQ) {
        ret = __ipc_smc_switch(irq);
        if (ret != MSPC_OK)
            tloge("MSPC: process ATF IPC irq failed!\n");
        return;
    }

    ret = mspc_lock_accessing();
    if (ret != MSPC_OK) {
        tloge("%s:lock mspc accessing failed!\n", __func__);
        mspc_ipc_irq_ctrl(false);
        return;
    }

    if (irq == IPC_TEE_MBXFIQ) {
        /* TEE fastboot irq, receive message. */
        mspc_receive_ipc(IPC_TEE_FASTMBOX);
    } else if (irq == IPC_TEE_ACK_MBXFIQ) {
        /* TEE normal irq, receive ACK. */
        if (mspc_ipc_is_ack(IPC_MSPC_FASTMBOX))
            mspc_ipc_recv_ack(IPC_MSPC_FASTMBOX);
        else
            tloge("MSPC:Invalid ACK!\n");
    } else {
        /* Invalid msp core ipc irq. */
        tloge("MSPC:Invalid irq:%u\n", irq);
    }

    mspc_unlock_accessing();
}

void mspc_ipc_irq_ctrl(bool enable)
{
    int32_t ret;

    if (enable) {
        ret = SRE_HwiEnable((HWI_HANDLE_T)IPC_TEE_MBXFIQ);
        if (ret != SRE_OK)
            tloge("MSPC:Enable irq %d error(0x%x).\n",
                  IPC_TEE_MBXFIQ, ret);

        ret = SRE_HwiEnable((HWI_HANDLE_T)IPC_TEE_ACK_MBXFIQ);
        if (ret != SRE_OK)
            tloge("MSPC:Enable irq %d error(0x%x).\n",
                  IPC_TEE_ACK_MBXFIQ, ret);
    } else {
        ret = SRE_HwiDisable((HWI_HANDLE_T)IPC_TEE_MBXFIQ);
        if (ret != SRE_OK)
            tloge("MSPC:Disable irq %d error(0x%x).\n",
                  IPC_TEE_MBXFIQ, ret);

        ret = SRE_HwiDisable((HWI_HANDLE_T)IPC_TEE_ACK_MBXFIQ);
        if (ret != SRE_OK)
            tloge("MSPC:Disable irq %d error(0x%x).\n",
                  IPC_TEE_ACK_MBXFIQ, ret);
    }
}

/**
 * @brief      : mspc_ipc_init : Initialize ipc interrupt and callback.
 */
int32_t mspc_ipc_init(void)
{
    int32_t ret;
    uint32_t i;
    HWI_HANDLE_T irq;

    g_ipc_cb_current_num = 0;
    /* Operation table init */
    for (i = 0; i < MAX_IPC_CALLBACK_NUM; i++)
        g_ipc_msg_ops[i].ipc_msg_cb = NULL;

    for (i = 0; i < ARRAY_SIZE(g_mspc_ipc_irq); i++) {
        irq = (HWI_HANDLE_T)g_mspc_ipc_irq[i];
        ret = SRE_HwiCreate(irq, MSPC_IRQ_PRIO, INT_SECURE,
                            (HWI_PROC_FUNC)mspc_ipc_irq_handler,
                            (HWI_ARG_T)irq);
        if (ret != SRE_OK) {
            tloge("MSPC:SRE_HwiCreate irq %d errorNO 0x%x\n", irq, ret);
            return MSPC_IPC_IRQ_ERR;
        }

        ret = SRE_HwiEnable(irq);
        if (ret != SRE_OK) {
            tloge("MSPC:SRE_HwiEnable irq %d errorNO 0x%x\n", irq, ret);
            return MSPC_IPC_IRQ_ERR;
        }
    }

    ret = pthread_mutex_init(&g_ipc_mutex, NULL);
    if (ret != SRE_OK) {
        tloge("MSPC: Create ipc mutex lock failed! ret=%d\n", ret);
        return MSPC_IPC_MUTEX_ERR;
    }

    return MSPC_OK;
}

int32_t mspc_ipc_resume(void)
{
    int32_t ret;
    uint32_t i;
    HWI_HANDLE_T irq;

    /* Resume MSPC ipc interrupt requestment. */
    for (i = 0; i < ARRAY_SIZE(g_mspc_ipc_irq); i++) {
        irq = g_mspc_ipc_irq[i];
        ret = SRE_HwiResume(irq, MSPC_IRQ_PRIO, INT_SECURE);
        if (ret != SRE_OK) {
            tloge("MSPC:SRE_HwiResume irq %d errorNO 0x%x\n", irq, ret);
            return MSPC_IPC_IRQ_ERR;
        }

        ret = SRE_HwiEnable(irq);
        if (ret != SRE_OK) {
            tloge("MSPC:SRE_HwiEnable irq %d errorNO 0x%x\n", irq, ret);
            return MSPC_IPC_IRQ_ERR;
        }
    }

    return MSPC_OK;
}
