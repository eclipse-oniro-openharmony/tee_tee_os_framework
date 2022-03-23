/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: acc device common function
 * Author: zhanglinhao zhanglinhao@huawei.com
 * Create: 2020-10
 */
#include "acc_common.h"
#include "hi_sec_dlv.h"
#include "tee_log.h"
#include "mem_ops.h"
#include "sec_api.h"
#include "register_ops.h"

#define  HISI_HAC_SUBCTRL_BASE_P0	0x000140070000
#define GET_IO_BASE(adev) (adev->hw_device->base_addr)
#define GET_SUBCTRL_BASE(adev) (adev->hw_device->subctrl_addr)
#define  HISI_HAC_SUBCTRL_SIZE (0x10000)
static uint64_t sec_get_subctrl_base(uint32_t chip_id)
{
	uint64_t base;

	switch(chip_id) {
		case 0:
			base = HISI_HAC_SUBCTRL_BASE_P0;
			break;
		default:
			tloge("[%s][%d] chip id %d not support",
				__FUNCTION__, __LINE__, chip_id);
			return 0;
	}

	return base;
}

uint32_t readl_poll_timeout(void *addr, uint64_t time)
{
    SRE_SwMsleep(time);
    return readl((uintptr_t)addr);
}

static int sec_reset_request(struct acc_device *sec_dev)
{
	int32_t ret;
	uintptr_t base = GET_SUBCTRL_BASE(sec_dev);

	/* disable clock */
	writel(0x1, base + SC_SEC_ICG_DIS_REG);
	ret = readl_poll_timeout((void *)base + SC_SEC_ICG_ST_REG, SEC_POLL_TIMEOUT_MS);
	if (ret != 0x1010006) {
		tloge("fail to disable clock\n");
		return ret;
	}

	tlogi("reset\n");
	/* reset request */
	writel(0x3, base + SC_SEC_RESET_REQ_REG);
	ret = readl_poll_timeout((void *)base + SC_SEC_RESET_ST_REG, SEC_POLL_TIMEOUT_MS);
	if (ret != 3) {
		tloge("fail to send reset request\n");
		return ret;
	}

	tlogi("enable clock\n");
	/* enable clock */
	writel(0x1, base + SC_SEC_ICG_EN_REG);
	ret = readl_poll_timeout((void *)base + SC_SEC_ICG_ST_REG, SEC_POLL_TIMEOUT_MS);
	if (ret != 0x1010007) {
		tloge("fail to enable clock\n");
		return ret;
	}

	return 0;
}


int sec_engine_init(struct acc_device *sec_dev)
{
    uint32_t ret;
    uint32_t reg = 0;
    uintptr_t base = GET_IO_BASE(sec_dev) + ACC_ENGINE_PF_CFG_OFF + SEC_ACC_COMMON_REG_OFF;

    writel(0x1, base + SEC_MEM_START_INIT_REG);
    ret =readl_poll_timeout((void *)base + SEC_MEM_INIT_DONE_REG, SEC_POLL_TIMEOUT_MS);
    if (ret == 1) {
        tlogi("sec mem init done\n");
    } else {
        tloge("sec mem init fail\n");
        return ret;
    }

    reg = readl(base + SEC_CONTROL_REG);
    reg |= (0x1 << SEC_TRNG_EN_SHIFT);
    writel(reg, base + SEC_CONTROL_REG);
    reg = readl(base + SEC_INTERFACE_USER_CTRL0_REG);
    reg &= ~SEC_USER0_SMMU_NORMAL;
    writel(reg, base + SEC_INTERFACE_USER_CTRL0_REG);

    reg = readl(base + SEC_INTERFACE_USER_CTRL1_REG);
    reg &= ~SEC_USER1_SMMU_NORMAL;
    writel(reg, base + SEC_INTERFACE_USER_CTRL1_REG);

    writel(0xfffff7fd, base + SEC_BD_ERR_CHK_EN_REG(1));
    writel(0xffffbfff, base + SEC_BD_ERR_CHK_EN_REG(3));

    /*enable abnormal int*/
    writel(SEC_PF_INT_MSK, base + SEC_PF_ABNORMAL_INT_ENABLE_REG);
    writel(SEC_RAS_CE_ENB_MSK, base + SEC_RAS_CE_ENABLE_REG);
    writel(SEC_RAS_FE_ENB_MSK, base + SEC_RAS_FE_ENABLE_REG);
    writel(SEC_RAS_NFE_ENB_MSK, base + SEC_RAS_NFE_ENABLE_REG);

    /* enable clock gate control */
    reg = readl(base + SEC_CONTROL_REG);
    reg |= (1<<3);
    writel(reg, base + SEC_CONTROL_REG);

    /*config endian*/
    reg = readl(base + SEC_CONTROL_REG);
    reg |= sec_dev->endian;
    writel(reg, base + SEC_CONTROL_REG);

    return 0;
}

static int sec_revoke_reset(struct acc_device *sec_dev)
{
	int ret = 0;
	uintptr_t base = GET_SUBCTRL_BASE(sec_dev);

	tlogi("disable clk\n");
	/* disable clock */
	writel(0x1, base + SC_SEC_ICG_DIS_REG);
	ret = readl_poll_timeout((void *)base + SC_SEC_ICG_ST_REG, SEC_POLL_TIMEOUT_MS);
	if (ret != 0x1010006) {
		tloge("fail to disable clock\n");
		return ret;
	}
	
	tlogi("dereset\n");
	/* revoke reset */
	writel(0x3, base + SC_SEC_RESET_DREQ_REG);
	ret = readl_poll_timeout((void *)base + SC_SEC_RESET_ST_REG, SEC_POLL_TIMEOUT_MS);
	if (ret != 0) {
		tloge("fail to revoke reset\n");
		return ret;
	}
	
	tlogi("enable clk\n");
	/* enable clock */
	writel(1, base + SC_SEC_ICG_EN_REG);
	ret = readl_poll_timeout((void *)base + SC_SEC_ICG_ST_REG, SEC_POLL_TIMEOUT_MS);
	if (ret != 0x1010007) {
		tloge("fail to enable clock\n");
		return ret;
	}

	return 0;
}

int sec_soft_reset(struct acc_device *sec_dev)
{
    int ret;

    tlogi("send reset request\n");
    ret = sec_reset_request(sec_dev);
    if (ret) {
        tloge("fail to send reset 0x%x\n", ret);
        return ret;
    }

    tlogi("dereset request\n");
    SRE_SwMsleep(5);
    ret = sec_revoke_reset(sec_dev);
    if (ret) {
        tloge("fail to revoke reset 0x%x\n", ret);
        return ret;
    }
    tlogi("sec reset succeed\n");
    return 0;
}

static int sec_dev_vf_init(struct acc_device *sec_dev,  struct qm_func_ops *ops)
{
	int ret;
	struct qm_sq_config sq_config[2];
	struct qm_vf_config vf_config;

	qm_function_set_dev(&sec_dev->qm_func, (void *)(GET_IO_BASE(sec_dev) + ACC_QM_PF_OP_OFF));

	sq_config[0].burst_cnt_shift = 0;
	sq_config[0].depth = SEC_QUEUE_DEPTH / 2;

	sq_config[0].order = 0;
	sq_config[0].sq_num = (uint16_t)sec_dev->sq_num /2;
	sq_config[0].type = 0;

	sq_config[1].burst_cnt_shift = 0;
	sq_config[1].depth = SEC_QUEUE_DEPTH / 2;

	sq_config[1].order = 0;
	sq_config[1].sq_num = (uint16_t)sec_dev->sq_num /2;
	sq_config[1].type = 1;
	vf_config.sq_config = &sq_config[0];
	vf_config.sq_config_num = 2;
	vf_config.sqe_size = SEC_BD_SIZE;
	vf_config.cq_num = (uint16_t)sec_dev->sq_num;
	vf_config.cq_depth = SEC_QUEUE_DEPTH;
	vf_config.eq_depth = (uint16_t)((sec_dev->sq_num) * 2);
	vf_config.aeq_depth = SEC_QUEUE_DEPTH;

	vf_config.session_num = 16;
	vf_config.priv_data_size = sizeof(struct sec_task_property);
	ret = qm_function_init(&sec_dev->qm_func, &vf_config, ops);
	if (ret != 0) {
		tloge("fail to init qm function\n");
		return ret;
	}
	tlogi("init qm function ok\n");
	return ret;
}

static uint32_t sec_get_chip_id(void)
{
	return 0;
}

static void sec_get_dfx_info(void)
{
}

int acc_dev_pf_init(struct acc_device *adev)
{
    int ret;

    ret = qm_pf_init(&adev->qm_func, (void *)GET_IO_BASE(adev) + ACC_QM_PF_CFG_OFF);
    if (ret != 0) {
        tloge("Failed to init pf info ret:%d\n", ret);
        return ret;
    }
    tlogi("qm pf init ok\n");

    qm_set_smmu(&adev->qm_func, 0);
    adev->smmu_normal = false;

    return 0;
}

int acc_dev_init(struct acc_device *adev)
{
    struct acc_hw_device_data *hw_data = adev->hw_device;
    struct sqc_vft_config vft_sqc;
    struct cqc_vft_config vft_cqc;
    u32 i;
    int ret;

    tlogi("Enter acc device init process\n");
    if (!hw_data) {
        tloge("Failed to init device, hw_data not set\n");
        return -EFAULT;
    }

    if (hw_data->reset_device(adev)) {
        tloge("Failed to reset device\n");
        return -EFAULT;
    }
    tlogi("acc device reset ok\n");

    if (hw_data->init_pf(adev)) {
        tloge("Failed to init pf info\n");
        return -EFAULT;
    }
    tlogi("acc device init pf ok\n");

    vft_sqc.sq_num = (uint16_t)adev->sq_num;
    vft_sqc.valid = 1;
    vft_cqc.valid = 1;
    for (i = 0; i < adev->num_vfs + 1; i++) {
        ret = qm_pf_config_vft(&adev->qm_func, i, &vft_sqc, &vft_cqc);
        if (ret) {
            tloge("fail to init vft\n");
            return ret;
        }
    }
    tlogi("PF init succeed\n");

    ret = hw_data->init_device(adev);
    if (ret) {
        tloge("fail to init  engine\n");
        return ret;
    }
    tlogi("device init ok\n");

    return 0;
}

void acc_init_hw_data_sec(struct acc_hw_device_data *hw_data)
{
    hw_data->priv_data_size = sizeof(struct sec_task_property);
    hw_data->subctrl_size = HISI_HAC_SUBCTRL_SIZE;
    hw_data->init_device = sec_engine_init;
    hw_data->reset_device = sec_soft_reset;
    hw_data->get_subctrl_base = sec_get_subctrl_base;
    hw_data->init_pf = acc_dev_pf_init;
    hw_data->init_vf = sec_dev_vf_init;
    hw_data->get_chip_id = sec_get_chip_id;
    hw_data->get_device_dfx_info = sec_get_dfx_info;
}
