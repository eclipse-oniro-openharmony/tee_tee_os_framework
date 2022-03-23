/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2019. All rights reserved.
 * Description: SEC BD队列管理代码
 * Author: o00302765
 * Create: 2019-10-22
 */
//#include <hisilicon/chip/level_2/hi_sdk_l2.h>

#include "hi_sec_common.h"
#include "hi_sec_reg_crg_dio.h"
#include "hi_sec_reg_sec.h"
#include "hi_sec_drv.h"
#include "tee_log.h"

#define HI_SEC_CH0_INT  94
#define HI_SEC_CH1_INT  95
#define HI_SEC_CH2_INT  96
#define HI_SEC_CH3_INT  97
#define HI_SEC_CH4_INT  98
#define HI_SEC_CH5_INT  99
#define HI_SEC_CH6_INT  100
#define HI_SEC_CH7_INT  101

struct hi_sec_drv_ptr_s {
	hi_uint32 ptr: 10;
	hi_uint32 rscv: 22;
};

struct hi_sec_drv_s {
	void *buf;
	uintptr_t buf_dma;
	struct hi_sec_bd_desc_s *bdq[HI_SEC_BD_QNUM];
	hi_uint32 bdq_dma[HI_SEC_BD_QNUM];
	struct hi_sec_drv_cblist_s *cblist[HI_SEC_BD_QNUM];
	struct hi_sec_drv_ptr_s curr_ptr[HI_SEC_BD_QNUM];
	struct hi_sec_cnt_s sta;
};

static struct hi_sec_drv_s g_secdrv;

static hi_uint32 g_ch_base_tb[] = {
	HI_SDK_L0_REG_SEC_SEC_CH0_BASE_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH1_BASE_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH2_BASE_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH3_BASE_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH4_BASE_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH5_BASE_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH6_BASE_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH7_BASE_BASE,
};

static hi_uint32 g_sprt_tb[] = {
	HI_SDK_L0_REG_SEC_SEC_CH0_SPRT_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH1_SPRT_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH2_SPRT_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH3_SPRT_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH4_SPRT_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH5_SPRT_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH6_SPRT_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH7_SPRT_BASE,
};

static hi_uint32 g_eprt_tb[] = {
	HI_SDK_L0_REG_SEC_SEC_CH0_EPRT_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH1_EPRT_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH2_EPRT_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH3_EPRT_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH4_EPRT_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH5_EPRT_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH6_EPRT_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH7_EPRT_BASE,
};

static hi_uint32 g_int_mask_tb[] = {
	HI_SDK_L0_REG_SEC_SEC_CH0_INT_MASK_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH1_INT_MASK_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH2_INT_MASK_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH3_INT_MASK_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH4_INT_MASK_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH5_INT_MASK_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH6_INT_MASK_BASE,
	HI_SDK_L0_REG_SEC_SEC_CH7_INT_MASK_BASE,
};

static inline void hi_sec_qinit(hi_uint32 qid, hi_uint32 addr)
{
	struct hi_sdk_l0_reg_sec_sec_ch0_base_s ch_base;
	ch_base.sec_ch0_base = addr;
	hi_sdk_l0_write_reg(g_ch_base_tb[qid], (hi_uint32 *)&ch_base);
}

static inline void hi_sec_drv_sptr_get(hi_uint32 qid,
		struct hi_sec_drv_ptr_s *ptr)
{
	hi_sdk_l0_read_reg(g_sprt_tb[qid], (hi_uint32 *)ptr);
}

static inline void hi_sec_drv_eptr_get(hi_uint32 qid,
		struct hi_sec_drv_ptr_s *ptr)
{
	hi_sdk_l0_read_reg(g_eprt_tb[qid], (hi_uint32 *)ptr);
}

static inline void hi_sec_drv_eptr_plus(hi_uint32 qid)
{
	struct hi_sdk_l0_reg_sec_sec_ch0_eprt_s ch_eprt;
	hi_sdk_l0_read_reg(g_eprt_tb[qid], (hi_uint32 *)&ch_eprt);
	ch_eprt.sec_ch0_eprt++;
	hi_sdk_l0_write_reg(g_eprt_tb[qid], (hi_uint32 *)&ch_eprt);
}

static inline void hi_sec_int_mask(hi_uint32 qid, hi_uint32 mask)
{
	struct hi_sdk_l0_reg_sec_sec_ch0_int_mask_s int_mask;
	hi_sdk_l0_read_reg(g_int_mask_tb[qid], (hi_uint32 *)&int_mask);
	int_mask.sec_ch0_int_mask = mask;
	hi_sdk_l0_write_reg(g_int_mask_tb[qid], (hi_uint32 *)&int_mask);
}

/* SEC模块复位撤离 */
void hi_sec_srst_n(void)
{
	struct hi_sec_reg_crg_dio_sc_rst_protect_s sc_rst;

	hi_sdk_l0_read_reg(HI_SEC_REG_CRG_DIO_SC_RST_PROTECT_BASE,
		(hi_uint32 *)&sc_rst);
	/* 复位 */
	sc_rst.sec_srst_n= 0;
	sc_rst.pke_srst_n = 0;
	sc_rst.kdf_srst_n= 0;
	sc_rst.trng_srst_n= 0;
	hi_sdk_l0_write_reg(HI_SEC_REG_CRG_DIO_SC_RST_PROTECT_BASE,
		(hi_uint32 *)&sc_rst);
	hi_udelay(10);

	/* 撤销复位 */
	hi_sdk_l0_read_reg(HI_SEC_REG_CRG_DIO_SC_RST_PROTECT_BASE,
		(hi_uint32 *)&sc_rst);
	sc_rst.sec_srst_n= 1;
	sc_rst.pke_srst_n = 1;
	sc_rst.kdf_srst_n= 1;
	sc_rst.trng_srst_n= 1;
	hi_sdk_l0_write_reg(HI_SEC_REG_CRG_DIO_SC_RST_PROTECT_BASE,
		(hi_uint32 *)&sc_rst);
	hi_udelay(10);

	hi_secdrv_systrace(HI_RET_SUCC, 0, 0, 0, 0);
	return;
}

/* SEC模块时钟使能 */
void hi_sec_clk_en(void)
{
	struct hi_sec_reg_crg_dio_sc_per_clk_en0_s clk_en0;
	struct hi_sec_reg_crg_dio_sc_per_clk_en1_s clk_en1;

	hi_sdk_l0_read_reg(HI_SEC_REG_CRG_DIO_SC_PER_CLK_EN0_BASE,
		(hi_uint32 *)&clk_en0);
	clk_en0.trng_clk_en = 1;
	clk_en0.kdf_clk_en = 1;
	hi_sdk_l0_write_reg(HI_SEC_REG_CRG_DIO_SC_PER_CLK_EN0_BASE,
		(hi_uint32 *)&clk_en0);

	hi_sdk_l0_read_reg(HI_SEC_REG_CRG_DIO_SC_PER_CLK_EN1_BASE,
		(hi_uint32 *)&clk_en1);
	clk_en1.pke_clk_en = 1;
	clk_en1.sec_clk_en = 1;
	hi_sdk_l0_write_reg(HI_SEC_REG_CRG_DIO_SC_PER_CLK_EN1_BASE,
		(hi_uint32 *)&clk_en1);
	hi_udelay(10);

	hi_secdrv_systrace(HI_RET_SUCC, 0, 0, 0, 0);
	return;
}

/* BD错误统计 */
static void hi_sec_drv_err_sta(hi_uint32 qid, hi_uint32 bdalarm,
				  hi_uint32 authfail)
{
	if (bdalarm & HI_SEC_DRV_BD_SM3_ALARM)
		g_secdrv.sta.data_sta[qid].bdalarm_sm3err++;

	if (bdalarm & HI_SEC_DRV_BD_SM4_ALARM)
		g_secdrv.sta.data_sta[qid].bdalarm_sm4err++;

	if (bdalarm & HI_SEC_DRV_BD_KEY_ALARM)
		g_secdrv.sta.data_sta[qid].bdalarm_keyerr++;

	if (bdalarm & HI_SEC_DRV_BD_DATA_ALARM)
		g_secdrv.sta.data_sta[qid].bdalarm_pkterr++;

	if (authfail)
		g_secdrv.sta.data_sta[qid].auth_fail++;
}

/* BD描述符回收处理 */
static hi_int32 hi_sec_drv_tasklet(hi_uint32 qid)
{
	struct hi_sec_bd_desc_s *dst_desc = HI_NULL;
	struct hi_sec_drv_ptr_s sptr;
	hi_uint32 xcm_auth_fail;
	hi_uint32 err = 0;
	hi_int32 ret = HI_RET_SUCC;

	/* 没有BD描述符回收 */
	hi_sec_drv_sptr_get(qid, &sptr);
	if (g_secdrv.curr_ptr[qid].ptr == sptr.ptr) {
		hi_secdrv_systrace(HI_RET_FAIL, qid,
				   g_secdrv.curr_ptr[qid].ptr, sptr.ptr, 0);
		return HI_RET_FAIL;
	}

	do {
		dst_desc = g_secdrv.bdq[qid] + g_secdrv.curr_ptr[qid].ptr;

		hi_secdrv_systrace(HI_RET_SUCC, qid,
				   g_secdrv.curr_ptr[qid].ptr, dst_desc->bits.bd_alarm,
				   xcm_auth_fail);
		g_secdrv.sta.data_sta[qid].output++;

		xcm_auth_fail = dst_desc->bits.task_flag &
				   HI_SEC_DRV_TASK_FLAG_AES_XCM_AUTH_FAIL;
		hi_sec_drv_err_sta(qid, dst_desc->bits.bd_alarm, xcm_auth_fail);

		err = dst_desc->bits.bd_alarm | xcm_auth_fail;

		/* 出错不退出, 尽力而为回收所有描述符 */
		if (err) {
			hi_secdrv_systrace(HI_RET_FAIL, qid,
					   g_secdrv.curr_ptr[qid].ptr, dst_desc->bits.bd_alarm,
					   xcm_auth_fail);
			ret = HI_RET_FAIL;
		}

		g_secdrv.curr_ptr[qid].ptr++;
		hi_sec_drv_sptr_get(qid, &sptr);

	} while (g_secdrv.curr_ptr[qid].ptr != sptr.ptr);

	hi_secdrv_systrace(ret, qid, 0, 0, 0);
	return ret;
}

/*
 * BD描述符同步处理，用于对称加解密和摘要算法
 * 输入参数: struct hi_sec_bd_desc_s *desc 描述符
 *           hi_uint32 num, 描述符个数
 *           hi_uint32 qid  指定的QID
 */
static hi_int32 hi_sec_bd_insert(struct hi_sec_bd_desc_s *desc, hi_uint32 num,
				 hi_uint32 qid)
{
	struct hi_sec_bd_desc_s *dst_desc = HI_NULL;
	struct hi_sec_drv_ptr_s eptr;
	hi_uint32 index;
	struct hi_sec_drv_ptr_s tmp_ptr;
	struct hi_sec_bd_desc_s *bdq_head = HI_NULL;
	struct hi_sec_drv_data_sta_s *sta = HI_NULL;
	hi_int32 ret;

	if (desc == HI_NULL)
		return HI_RET_NULLPTR;

	if (num == 0 || num >= HI_SEC_BD_LEN || qid != 0)
		return HI_RET_INVALID_PARA;

	bdq_head = g_secdrv.bdq[qid];
	sta = &(g_secdrv.sta.data_sta[qid]);

	for (index = 0; index < num; index++, desc++) {
		hi_sec_drv_eptr_get(qid, &eptr);

		/* 队列已满 */
		tmp_ptr.ptr = eptr.ptr + 1;
		if (tmp_ptr.ptr == g_secdrv.curr_ptr[qid].ptr) {
			hi_printk("warning!! sec fifo full\r\n");
			return HI_RET_ITEM_FULL;
		}

		dst_desc = bdq_head + eptr.ptr;
		ret = memcpy_s(dst_desc, sizeof(*dst_desc), desc, sizeof(*desc));
		if (ret) {
			hi_secdrv_systrace(ret, 0, 0, 0, 0);
			return ret;
		}
		dst_desc->bits.ch_id = qid;

		/* 确保描述符数据已经更新到DDR */
		hi_sec_dsb();

		/* 写指针前移, 启动SEC引擎工作 */
		hi_sec_drv_eptr_plus(qid);
		hi_sec_drv_eptr_get(qid, &eptr); //
		hi_printk("eptr = %d\n", eptr.ptr);
		sta->input++;
	}

	ret = hi_sec_drv_tasklet(qid);
	hi_secdrv_systrace(ret, qid, 0, 0, 0);
	return ret;
}

hi_int32 hi_sec_bd_proc(struct hi_sec_bd_desc_s *desc, hi_uint32 num)
{
	return hi_sec_bd_insert(desc, num, 0);
}

/* 获取DFX统计 */
hi_int32 hi_sec_cnt_get(struct hi_sec_cnt_s *cnt)
{
	if (cnt == HI_NULL) {
		hi_secdrv_systrace(HI_RET_NULLPTR, 0, 0, 0, 0);
		return HI_RET_NULLPTR;
	}

	if (memcpy_s(cnt, sizeof(*cnt),&g_secdrv.sta, sizeof(g_secdrv.sta)))
		return HI_RET_FAIL;

	hi_secdrv_systrace(HI_RET_SUCC, 0, 0, 0, 0);
	return HI_RET_SUCC;
}

/* 获取SEC状态 */
hi_int32 hi_sec_sta_get(struct hi_sec_sta_s *sta)
{
	hi_uint32 qid;

	if (sta == HI_NULL) {
		hi_secdrv_systrace(HI_RET_NULLPTR, 0, 0, 0, 0);
		return HI_RET_NULLPTR;
	}

	for (qid = 0; qid < HI_SEC_BD_QNUM; qid++) {
		hi_sec_drv_sptr_get(qid, (struct hi_sec_drv_ptr_s *)&sta->ptr[qid].sptr);
		hi_sec_drv_eptr_get(qid, (struct hi_sec_drv_ptr_s *)&sta->ptr[qid].eptr);
		sta->ptr[qid].curr = g_secdrv.curr_ptr[qid].ptr;
	}

	hi_secdrv_systrace(HI_RET_SUCC, 0, 0, 0, 0);
	return HI_RET_SUCC;
}

/* SEC驱动初始化 */
hi_int32 hi_sec_drv_init(void)
{
	struct hi_sdk_l0_reg_sec_sec_chx_cfg_ok_s cfg_ok;
	hi_uint32 align;

	tlogi("hi_sec_drv_init start\n");
	hi_sec_clk_en();
	hi_sec_srst_n();

	if (memset_s(&g_secdrv, sizeof(g_secdrv), 0, sizeof(g_secdrv)))
		return HI_RET_FAIL;

    uint32_t size = (sizeof(struct hi_sec_bd_desc_s) * (HI_SEC_BD_LEN + 1));
    g_secdrv.buf = malloc_coherent(size);
	if (g_secdrv.buf == HI_NULL)
		return HI_RET_MALLOC_FAIL;

    g_secdrv.buf_dma = (hi_uint32)virt_mem_to_phys(g_secdrv.buf);

	/* 基地址64 bytes对齐 */
	align = (g_secdrv.buf_dma & (~(0x3f))) + sizeof(struct hi_sec_bd_desc_s) - g_secdrv.buf_dma;
	g_secdrv.bdq[0] = (struct hi_sec_bd_desc_s *)((hi_uint32)g_secdrv.buf + align);
	g_secdrv.bdq_dma[0] = g_secdrv.buf_dma + align;

	/* 启动配置芯片SEC队列 */
	if (memset_s(&cfg_ok, sizeof(cfg_ok), 0, sizeof(cfg_ok)))
		return HI_RET_FAIL;
	cfg_ok.sec_ch0_cfg_ok = HI_FALSE;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_SEC_SEC_CHX_CFG_OK_BASE, (hi_uint32 *)&cfg_ok);

	/* 配置队列基地址 */
	hi_sec_qinit(0, g_secdrv.bdq_dma[0]);

	/* 配置中断阈值和超时时间, 根据实测情况确定 */

	/* 关闭中断 */
	hi_sec_int_mask(0, HI_TRUE);
	hi_sec_int_mask(1, HI_TRUE);
	hi_sec_int_mask(2, HI_TRUE);
	hi_sec_int_mask(3, HI_TRUE);
	hi_sec_int_mask(4, HI_TRUE);
	hi_sec_int_mask(5, HI_TRUE);
	hi_sec_int_mask(6, HI_TRUE);
	hi_sec_int_mask(7, HI_TRUE);

	/* 完成配置芯片SEC队列 */
	if (memset_s(&cfg_ok, sizeof(cfg_ok), 0, sizeof(cfg_ok)))
		return HI_RET_FAIL;
	cfg_ok.sec_ch0_cfg_ok = HI_TRUE;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_SEC_SEC_CHX_CFG_OK_BASE,
		 (hi_uint32 *)&cfg_ok);

	tlogi("hi_sec_drv_init end\n");
	return HI_RET_SUCC;
}

/* SEC驱动去初始化 */
void hi_sec_drv_exit(void)
{
	hi_sec_free_phyaddr((sizeof(struct hi_sec_bd_desc_s) * (HI_SEC_BD_LEN + 1)),
			    g_secdrv.buf, g_secdrv.buf_dma);
}
