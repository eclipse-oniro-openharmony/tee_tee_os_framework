/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */
#include "eicc_platform.h"
#include "eicc_dts.h"
#include "eicc_device.h"
#include "eicc_driver.h"
#include "eicc_core.h"
#include "eicc_pmsr.h"

#define EICC_PM_DBG_STEPS_CNT 4

struct eicc_pm_dbg {
    u32 s_times;                        /* 成功的睡眠次数 */
    u32 r_times;                        /* 成功的唤醒次数 */
    u32 sr_stat[EICC_PM_DBG_STEPS_CNT]; /* 一次睡眠唤醒的记录 */
    u32 chn_id;                         /* 最新睡眠失败通道 */
    u32 last_step;                      /* 最新睡眠失败通道失败位置 */
};

struct eicc_pm_dbg g_eicc_pm_dbg;

void eicc_pm_disable_all_opipe(void)
{
    u32 idx = 0;
    struct eicc_device *pdev = NULL;
    struct eicc_channel *pchannel = NULL;
    while (eicc_dev_chn_get_byidx(idx, &pdev, &pchannel) == 0) {
        idx++;
        if (pchannel->state != EICC_CHN_OPEN) {
            continue;
        }

        if (isMsgRecvChn(pchannel)) {
            pchannel->state = EICC_CHN_OSUSPENDING;
            continue;
        }
        eicc_opipe_local_dis(pdev->base_va, EICC_GET_PIPE_ID(pchannel->ldrvchn_id));
        pchannel->state = EICC_CHN_OSUSPENDING;
    };
    return;
}

int eicc_pm_checkpd_all_opipe(void)
{
    int ret;
    u32 idx = 0;
    struct eicc_device *pdev = NULL;
    struct eicc_channel *pchannel = NULL;
    struct eicc_pm_dbg *eicc_pm_dbg = &g_eicc_pm_dbg;

    while (eicc_dev_chn_get_byidx(idx, &pdev, &pchannel) == 0) {
        idx++;
        if (pchannel->state != EICC_CHN_OSUSPENDING) {
            continue;
        }
        if (isMsgRecvChn(pchannel)) {
            pchannel->state = EICC_CHN_OSUSPENDED;
            continue;
        }

        ret = opipe_status_check(pdev->base_va, EICC_GET_PIPE_ID(pchannel->ldrvchn_id));
        if (ret) {
            if (eicc_pm_dbg->chn_id != pchannel->user_id) {
                eicc_print_error("channel %d pm opipe ret %d\n", pchannel->user_id, ret);
            }
            eicc_pm_dbg->chn_id = pchannel->user_id;
            eicc_pm_dbg->last_step = (u32)ret;
            return ret;
        }
        pchannel->state = EICC_CHN_OSUSPENDED;
    };
    return 0;
}

void eicc_pm_disable_all_ipipe(void)
{
    u32 idx = 0;
    struct eicc_device *pdev = NULL;
    struct eicc_channel *pchannel = NULL;

    while (eicc_dev_chn_get_byidx(idx, &pdev, &pchannel) == 0) {
        idx++;
        if (pchannel->state != EICC_CHN_OSUSPENDED) {
            continue;
        }
        if (pchannel->type == EICC_CHN_TYPE_MSG_INRSEND || pchannel->type == EICC_CHN_TYPE_DMA) {
            pchannel->state = EICC_CHN_ISUSPENDING;
            continue;
        }
        eicc_ipipe_local_dis(pdev->base_va, EICC_GET_PIPE_ID(pchannel->ldrvchn_id));
        pchannel->state = EICC_CHN_ISUSPENDING;
    };
}

int eicc_pm_checkpd_all_ipipe(void)
{
    int ret;
    u32 idx = 0;
    struct eicc_device *pdev = NULL;
    struct eicc_channel *pchannel = NULL;
    struct eicc_pm_dbg *eicc_pm_dbg = &g_eicc_pm_dbg;

    while (eicc_dev_chn_get_byidx(idx, &pdev, &pchannel) == 0) {
        idx++;
        if (pchannel->state != EICC_CHN_ISUSPENDING) {
            continue;
        }
        if (pchannel->type == EICC_CHN_TYPE_MSG_INRSEND || pchannel->type == EICC_CHN_TYPE_DMA) {
            pchannel->state = EICC_CHN_ISUSPENDED;
            continue;
        }
        ret = ipipe_neg_check(pdev->base_va, EICC_GET_PIPE_ID(pchannel->ldrvchn_id));
        if (ret == 0) {
            ret = ipipe_status_check(pdev->base_va, EICC_GET_PIPE_ID(pchannel->ldrvchn_id));
        }
        if (ret) {
#if !EICC_FEATURE_PM_ROLLBACK
            /* 在不支持rollback的系统中， 不能依赖recovery来重新发起低功耗协商过程 */
            eicc_ipipe_local_en(pdev->base_va, EICC_GET_PIPE_ID(pchannel->ldrvchn_id));
            pchannel->state = EICC_CHN_OSUSPENDED;
#endif
            if (eicc_pm_dbg->chn_id != pchannel->user_id) {
                eicc_print_error("channel %d pm ipipe ret %d\n", pchannel->user_id, ret);
            }
            eicc_pm_dbg->chn_id = pchannel->user_id;
            eicc_pm_dbg->last_step = (u32)ret;
            return ret;
        }
        pchannel->state = EICC_CHN_ISUSPENDED;
    };
    return 0;
}

int eicc_pm_check_pipe_empty(void)
{
    u32 idx = 0;
    struct eicc_device *pdev = NULL;
    struct eicc_channel *pchannel = NULL;

#if EICC_FEATURE_PM_EMPTYCHECK
    union ipipe_stat i_state = { 0 };
    union opipe_stat o_state = { 0 };
    struct eicc_pm_dbg *eicc_pm_dbg = &g_eicc_pm_dbg;

    while (eicc_dev_chn_get_byidx(idx, &pdev, &pchannel) == 0) {
        idx++;
        if (pchannel->state != (u32)EICC_CHN_ISUSPENDED) {
            continue;
        }
        if (isMsgRecvChn(pchannel)) {
            i_state.val = eicc_ipipe_local_status(pdev->base_va, EICC_GET_PIPE_ID(pchannel->ldrvchn_id));
            if (!i_state.union_stru.is_empty) {
                eicc_pm_dbg->chn_id = pchannel->user_id;
                eicc_pm_dbg->last_step = (u32)EICC_ERR_PM_IPIPE_NOT_EMPTY;
                return -1;
            }
        } else {
            o_state.val = eicc_opipe_local_status(pdev->base_va, EICC_GET_PIPE_ID(pchannel->ldrvchn_id));
            if (!o_state.union_stru.is_empty) {
                eicc_pm_dbg->chn_id = pchannel->user_id;
                eicc_pm_dbg->last_step = (u32)EICC_ERR_PM_OPIPE_NOT_EMPTY;
                return -1;
            }
        }
        pchannel->state = EICC_CHN_SUSPENDED;
    };
#else
    while (eicc_dev_chn_get_byidx(idx, &pdev, &pchannel) == 0) {
        idx++;
        if (pchannel->state != (u32)EICC_CHN_ISUSPENDED) {
            continue;
        }
        pchannel->state = EICC_CHN_SUSPENDED;
    }
#endif
    return 0;
}

static void eicc_pm_irqs_disable(void)
{
#if EICC_FEATURE_PM_IRQSCTRL
    u32 idx;
    u32 iidx;
    struct eicc_device *pdev = NULL;
    struct irq_bundle *bundle = NULL;
    for (idx = 0; idx < EICC_DEVICE_NUM_MAX; idx++) {
        pdev = eicc_device_get_fast(idx);
        if (pdev == NULL) {
            continue;
        }
        for (iidx = 0; iidx < sizeof(pdev->maps) / sizeof(pdev->maps[0]); iidx++) {
            bundle = pdev->maps[idx];
            if (bundle == NULL) {
                continue;
            }
            if (pdev->ctrl_level == EICC_DEV_CONTROL_LEVEL_HOST || pdev->ctrl_level == EICC_DEV_CONTROL_LEVEL_GUEST) {
                eicc_disable_irq(bundle->irq[0x0]);
                eicc_disable_irq(bundle->irq[0x1]);
            } else if (pdev->ctrl_level == EICC_DEV_CONTROL_LEVEL_IRQCLR) {
                eicc_disable_irq(bundle->irq[0x0]);
            } else {
                ; /* nothing need to do */
            }
        }
    }
#endif
    return;
}
static void eicc_pm_irqs_enable(void)
{
#if EICC_FEATURE_PM_IRQSCTRL
    u32 idx;
    u32 iidx;
    struct eicc_device *pdev = NULL;
    struct irq_bundle *bundle = NULL;
    for (idx = 0; idx < EICC_DEVICE_NUM_MAX; idx++) {
        pdev = eicc_device_get_fast(idx);
        if (pdev == NULL) {
            continue;
        }
        for (iidx = 0; iidx < sizeof(pdev->maps) / sizeof(pdev->maps[0]); iidx++) {
            bundle = pdev->maps[idx];
            if (bundle == NULL) {
                continue;
            }
            if (pdev->ctrl_level == EICC_DEV_CONTROL_LEVEL_HOST || pdev->ctrl_level == EICC_DEV_CONTROL_LEVEL_GUEST) {
                eicc_enable_irq(bundle->irq[0x0]);
                eicc_enable_irq(bundle->irq[0x1]);
            } else if (pdev->ctrl_level == EICC_DEV_CONTROL_LEVEL_IRQCLR) {
                eicc_enable_irq(bundle->irq[0x0]);
            } else {
                ; /* nothing need to do */
            }
        }
    }
#endif
    return;
}

static void eicc_pm_recovery(void)
{
#if EICC_FEATURE_PM_ROLLBACK
    u32 idx = 0;
    struct eicc_device *pdev = NULL;
    struct eicc_channel *pchannel = NULL;

    while (eicc_dev_chn_get_byidx(idx, &pdev, &pchannel) == 0) {
        idx++;
        if (pchannel->state == EICC_CHN_INIT || pchannel->state == EICC_CHN_OPEN ||
            pchannel->state == EICC_CHN_OPENNOSR) {
            continue;
        }

        if (isMsgRecvChn(pchannel)) {
            eicc_ipipe_local_en(pdev->base_va, EICC_GET_PIPE_ID(pchannel->ldrvchn_id));
            pchannel->state = (u32)EICC_CHN_OPEN;
        } else if (pchannel->type == EICC_CHN_TYPE_MSG_OUTSEND) {
            eicc_ipipe_local_en(pdev->base_va, EICC_GET_PIPE_ID(pchannel->ldrvchn_id));
            eicc_opipe_local_en(pdev->base_va, EICC_GET_PIPE_ID(pchannel->ldrvchn_id));
            pchannel->state = (u32)EICC_CHN_OPEN;
        } else {
            eicc_opipe_local_en(pdev->base_va, EICC_GET_PIPE_ID(pchannel->ldrvchn_id));
            pchannel->state = (u32)EICC_CHN_OPEN;
        }
    };
    return;
#endif
}

static void eicc_pm_chn_save_config(void)
{
    u32 idx = 0;
    struct eicc_device *pdev = NULL;
    struct eicc_channel *pchannel = NULL;

    while (eicc_dev_chn_get_byidx(idx, &pdev, &pchannel) == 0) {
        idx++;
        if (pchannel->state != EICC_CHN_SUSPENDED) {
            continue;
        }
        if (pchannel->opipe_cfg != NULL) {
            pchannel->opipe_cfg->rptr = eicc_opipe_rptr_get(pdev->base_va, EICC_GET_PIPE_ID(pchannel->ldrvchn_id));
        }
        if (pchannel->ipipe_cfg != NULL) {
            pchannel->ipipe_cfg->wptr = eicc_ipipe_wptr_get(pdev->base_va, EICC_GET_PIPE_ID(pchannel->ldrvchn_id));
        }
    };
    return;
}

int eicc_chn_suspend(void)
{
    int ret;
    struct eicc_pm_dbg *eicc_pm_dbg = &g_eicc_pm_dbg;

    eicc_pm_dbg->sr_stat[0x0]++;

    eicc_pm_disable_all_opipe();
    ret = eicc_pm_checkpd_all_opipe();
    if (ret) {
        eicc_pm_recovery();
        eicc_pm_dbg->sr_stat[0x1]++;
        return ret;
    }

    eicc_pm_disable_all_ipipe();
    ret = eicc_pm_checkpd_all_ipipe();
    if (ret) {
        eicc_pm_recovery();
        eicc_pm_dbg->sr_stat[0x2]++;
        return ret;
    }

    ret = eicc_pm_check_pipe_empty();
    if (ret) {
        eicc_pm_recovery();
        eicc_pm_dbg->sr_stat[0x3]++;
        return ret;
    }
    eicc_pm_irqs_disable();
    eicc_pm_chn_save_config();
    eicc_pm_dbg->s_times++;
    return 0;
}

void eicc_chn_resume(void)
{
    u32 idx = 0;
    struct eicc_device *pdev = NULL;
    struct eicc_channel *pchannel = NULL;
    struct eicc_pm_dbg *eicc_pm_dbg = &g_eicc_pm_dbg;

    while (eicc_dev_chn_get_byidx(idx, &pdev, &pchannel) == 0) {
        idx++;
        /* 只处理 EICC_CHN_SUSPENDED 状态的通道 */
        if (pchannel->state != EICC_CHN_SUSPENDED) {
            continue;
        }
        if (isMsgRecvChn(pchannel)) {
            eicc_ipipe_enable(pdev, pchannel);
        } else if (pchannel->type == EICC_CHN_TYPE_MSG_OUTSEND) {
            eicc_shadow_ipipe_enable(pdev, pchannel);
            eicc_opipe_enable(pdev, pchannel);
        } else {
            eicc_opipe_enable(pdev, pchannel);
        }
        pchannel->state = EICC_CHN_OPEN;
    };
    eicc_pm_irqs_enable();
    eicc_pm_dbg->r_times++;

    eicc_pm_dbg->sr_stat[0x0] = 0;
    eicc_pm_dbg->sr_stat[0x1] = 0;
    eicc_pm_dbg->sr_stat[0x2] = 0;
    eicc_pm_dbg->sr_stat[0x3] = 0;
    return;
}

static void eicc_seccfg_save(struct eicc_device *pdev, struct eicc_dev_bk *pdev_bk)
{
#if EICC_FEATURE_UNSECCHN_SUPPORT
    int idx;
    u32 opipe_regs[EICC_PIPE_SEC_REGS_CNT] = {EICC_OPIPE_SECCTRL0, EICC_OPIPE_SECCTRL1,
                                              EICC_OPIPE_SECCTRL2, EICC_OPIPE_SECCTRL3};
    u32 opipe_regs_v210[EICC_PIPE_SEC_REGS_CNT] = {EICC_V210_OPIPE_SECCTRL0, EICC_V210_OPIPE_SECCTRL1,
                                                   EICC_V210_OPIPE_SECCTRL2, EICC_V210_OPIPE_SECCTRL3};
    u32 ipipe_regs[EICC_PIPE_SEC_REGS_CNT] = {EICC_IPIPE_SECCTRL0, EICC_IPIPE_SECCTRL1,
                                              EICC_IPIPE_SECCTRL2, EICC_OPIPE_SECCTRL3};
    u32 ipipe_regs_v210[EICC_PIPE_SEC_REGS_CNT] = {EICC_V210_IPIPE_SECCTRL0, EICC_V210_IPIPE_SECCTRL1,
                                                   EICC_V210_IPIPE_SECCTRL2, EICC_V210_IPIPE_SECCTRL3};
    for (idx = 0; idx < EICC_PIPE_SEC_REGS_CNT; idx++) {
        if (pdev->version_id == EICC_HW_VERSION_V210) {
            pdev_bk->opipe_sec[idx] = readl((void *)((char *)pdev->base_va + opipe_regs_v210[idx]));
            pdev_bk->ipipe_sec[idx] = readl((void *)((char *)pdev->base_va + ipipe_regs_v210[idx]));
        } else {
            pdev_bk->opipe_sec[idx] = readl((void *)((char *)pdev->base_va + opipe_regs[idx]));
            pdev_bk->ipipe_sec[idx] = readl((void *)((char *)pdev->base_va + ipipe_regs[idx]));
        }
    }
    pdev_bk->core_secctrl = readl((void *)((char *)pdev->base_va + EICC_CORE_SECCTRL));
    pdev_bk->glb_secctrl = readl((void *)((char *)pdev->base_va + EICC_GLB_SECCTRL));
#endif
}

static void eicc_devbk_save(struct eicc_device *pdev, struct eicc_dev_bk *pdev_bk)
{
#if EICC_FEATURE_INNERCHN_SUPPORT
    u32 pipeid;
    /* 备份所有ipipe的int mask，备份所有安全寄存器 */
    for (pipeid = 0; pipeid < pdev->pipepair_cnt; pipeid++) {
        pdev_bk->ipipe_int_msk[pipeid] = readl((void *)((char *)pdev->base_va + EICC_IPIPE_INT_MASK(pipeid)));
    }
#endif
    eicc_seccfg_save(pdev, pdev_bk);
    pdev_bk->glb_ctrl = eicc_dev_glbctrl_get(pdev->base_va);
}

static void eicc_seccfg_restore(struct eicc_device *pdev, struct eicc_dev_bk *pdev_bk)
{
#if EICC_FEATURE_UNSECCHN_SUPPORT
    int idx;
    u32 opipe_regs[EICC_PIPE_SEC_REGS_CNT] = {EICC_OPIPE_SECCTRL0, EICC_OPIPE_SECCTRL1, EICC_OPIPE_SECCTRL2,
                                              EICC_OPIPE_SECCTRL3};
    u32 opipe_regs_v210[EICC_PIPE_SEC_REGS_CNT] = {EICC_V210_OPIPE_SECCTRL0, EICC_V210_OPIPE_SECCTRL1, EICC_V210_OPIPE_SECCTRL2,
                                                   EICC_V210_OPIPE_SECCTRL3};
    u32 ipipe_regs[EICC_PIPE_SEC_REGS_CNT] = {EICC_IPIPE_SECCTRL0, EICC_IPIPE_SECCTRL1, EICC_IPIPE_SECCTRL2,
                                              EICC_OPIPE_SECCTRL3};
    u32 ipipe_regs_v210[EICC_PIPE_SEC_REGS_CNT] = {EICC_V210_IPIPE_SECCTRL0, EICC_V210_IPIPE_SECCTRL1, EICC_V210_IPIPE_SECCTRL2,
                                                   EICC_V210_IPIPE_SECCTRL3};
    writel(pdev_bk->glb_secctrl | SECREG_EN_MASK, (void *)((char *)pdev->base_va + EICC_GLB_SECCTRL));
    writel(pdev_bk->core_secctrl | SECREG_EN_MASK, (void *)((char *)pdev->base_va + EICC_CORE_SECCTRL));
    for (idx = 0; idx < EICC_PIPE_SEC_REGS_CNT; idx++) {
        if (pdev->version_id == EICC_HW_VERSION_V210) {
            writel(pdev_bk->opipe_sec[idx] | SECREG_EN_MASK, (void *)((char *)pdev->base_va + opipe_regs_v210[idx]));
            writel(pdev_bk->ipipe_sec[idx] | SECREG_EN_MASK, (void *)((char *)pdev->base_va + ipipe_regs_v210[idx]));
        } else {
            writel(pdev_bk->opipe_sec[idx] | SECREG_EN_MASK, (void *)((char *)pdev->base_va + opipe_regs[idx]));
            writel(pdev_bk->ipipe_sec[idx] | SECREG_EN_MASK, (void *)((char *)pdev->base_va + ipipe_regs[idx]));
        }
    }
    pdev_bk->core_secctrl = readl((void *)((char *)pdev->base_va + EICC_CORE_SECCTRL));
    pdev_bk->glb_secctrl = readl((void *)((char *)pdev->base_va + EICC_GLB_SECCTRL));
#endif
}

static void eicc_devbk_restore(struct eicc_device *pdev, struct eicc_dev_bk *pdev_bk)
{
#if EICC_FEATURE_INNERCHN_SUPPORT
    u32 pipeid;
#endif
    eicc_dev_glbctrl_set(pdev->base_va, pdev_bk->glb_ctrl);
    eicc_seccfg_restore(pdev, pdev_bk);
#if EICC_FEATURE_INNERCHN_SUPPORT
    for (pipeid = 0; pipeid < pdev->pipepair_cnt; pipeid++) {
        writel(pdev_bk->ipipe_int_msk[pipeid], (void *)((char *)pdev->base_va + EICC_IPIPE_INT_MASK(pipeid)));
    }
#endif
}

/* dev suspend 失败的时候，由pmsrhook负责进行eicc_chn_resume来恢复通道 */
int eicc_dev_suspend(void)
{
    u32 idx;
    struct eicc_device *pdev = NULL;
    struct eicc_dev_bk *pdev_bk = NULL;
    for (idx = 0; idx < EICC_DEVICE_NUM_MAX; idx++) {
        pdev = eicc_device_get_fast(idx);
        if (pdev == NULL) {
            continue;
        }
        if (pdev->ctrl_level != EICC_DEV_CONTROL_LEVEL_HOST) {
            continue;
        }
        if (pdev->devbk == NULL) {
            return -1;
        }
        pdev_bk = pdev->devbk;
        /* 应该检查glbctrl中的全局idle状态 */
        eicc_devbk_save(pdev, pdev_bk);
        pdev->state = EICC_DEV_STATE_SLEEPING;
    }

    return 0;
}

void eicc_dev_resume(void)
{
    u32 idx;
    struct eicc_device *pdev = NULL;
    struct eicc_dev_bk *pdev_bk = NULL;
    for (idx = 0; idx < EICC_DEVICE_NUM_MAX; idx++) {
        pdev = eicc_device_get_fast(idx);
        if (pdev == NULL) {
            continue;
        }
        /* restore dev configuration */
        if (pdev->ctrl_level == EICC_DEV_CONTROL_LEVEL_HOST) {
            pdev_bk = pdev->devbk;
            eicc_devbk_restore(pdev, pdev_bk);
        }
        pdev->state = EICC_DEV_STATE_WORKING;
    }

    return;
}

u32 eicc_pmsr_dump_save(u8 *buf, u32 len)
{
    u32 used_len = sizeof(g_eicc_pm_dbg);
    if (len < used_len) {
        return 0;
    }
    if (memcpy_s(buf, len, &g_eicc_pm_dbg, sizeof(g_eicc_pm_dbg))) {
        return 0;
    }
    return used_len;
}
