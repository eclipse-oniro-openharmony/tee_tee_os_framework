/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee hal demux impl
 * Author: SDK
 * Create: 2019-10-11
 */

#include "hi_type_dev.h"
#include "hi_tee_drv_mem.h"
#include "tee_hal_demux.h"
#include "tee_drv_demux_define.h"
#include "tee_drv_demux_reg.h"

/* process of bit */
#define hal_set_bit(src, bit)        ((src) |= (1U << (bit)))
#define hal_clear_bit(src, bit)       ((src) &= ~(1U << (bit)))

hi_void tee_dmx_hal_init_hw(hi_void)
{
    u_peri_crg205 peri_crg_205;
    u_peri_crg206 peri_crg_206;
    u_peri_crg207 peri_crg_207;

    peri_crg_205.u32 = dmx_read_reg(DMX_CRG_REGS_IOBASE, DMX_CRG_REGS205_OFFSET);
    peri_crg_206.u32 = dmx_read_reg(DMX_CRG_REGS_IOBASE, DMX_CRG_REGS206_OFFSET);
    peri_crg_207.u32 = dmx_read_reg(DMX_CRG_REGS_IOBASE, DMX_CRG_REGS207_OFFSET);

    /* check whether the clock has configured */
    if (peri_crg_206.bits.pvr_bus_cken == 1 &&
        peri_crg_206.bits.pvr_dmx_cken == 1) {
        return;
    }

    /* reset demux */
    peri_crg_206.bits.dmx_srst_req = 1;
    dmx_write_reg(DMX_CRG_REGS_IOBASE, DMX_CRG_REGS206_OFFSET, peri_crg_206.u32);

    peri_crg_206.bits.pvr_bus_cken     = 1;
    peri_crg_206.bits.pvr_dmx_cken     = 1;
    peri_crg_206.bits.pvr_27m_cken     = 1;
    peri_crg_205.bits.pvr_tsi1_cken    = 1;
    peri_crg_205.bits.pvr_tsi2_cken    = 1;
    peri_crg_205.bits.pvr_tsi3_cken    = 1;
    peri_crg_205.bits.pvr_tsi4_cken    = 1;
    peri_crg_205.bits.pvr_tsi5_cken    = 1;
    peri_crg_205.bits.pvr_tsi6_cken    = 1;
    peri_crg_205.bits.pvr_tsi7_cken    = 1;
    peri_crg_205.bits.pvr_tsi8_cken    = 1;
    peri_crg_206.bits.pvr_ts0_cken     = 1;
    peri_crg_206.bits.pvr_tsout0_cken  = 1;
    peri_crg_206.bits.pvr_tsout1_cken  = 1;
    peri_crg_206.bits.dmx_srst_req     = 0;

    dmx_write_reg(DMX_CRG_REGS_IOBASE, DMX_CRG_REGS205_OFFSET, peri_crg_205.u32);
    dmx_write_reg(DMX_CRG_REGS_IOBASE, DMX_CRG_REGS206_OFFSET, peri_crg_206.u32);

    peri_crg_207.bits.pvr_ts0_cksel = 1;
    peri_crg_207.bits.pvr_ts1_cksel = 1;

    dmx_write_reg(DMX_CRG_REGS_IOBASE, DMX_CRG_REGS207_OFFSET, peri_crg_207.u32);
}

hi_void tee_dmx_hal_deinit_hw(hi_void)
{
    u_peri_crg205 peri_crg_205;
    u_peri_crg206 peri_crg_206;
    u_peri_crg207 peri_crg_207;

    peri_crg_205.u32 = dmx_read_reg(DMX_CRG_REGS_IOBASE, DMX_CRG_REGS205_OFFSET);
    peri_crg_206.u32 = dmx_read_reg(DMX_CRG_REGS_IOBASE, DMX_CRG_REGS206_OFFSET);
    peri_crg_207.u32 = dmx_read_reg(DMX_CRG_REGS_IOBASE, DMX_CRG_REGS207_OFFSET);

    /* reset demux */
    peri_crg_206.bits.dmx_srst_req = 1;
    dmx_write_reg(DMX_CRG_REGS_IOBASE, DMX_CRG_REGS206_OFFSET, peri_crg_206.u32);

    peri_crg_206.bits.pvr_bus_cken     = 0;
    peri_crg_206.bits.pvr_dmx_cken     = 0;
    peri_crg_206.bits.pvr_27m_cken     = 0;
    peri_crg_205.bits.pvr_tsi1_cken    = 0;
    peri_crg_205.bits.pvr_tsi2_cken    = 0;
    peri_crg_205.bits.pvr_tsi3_cken    = 0;
    peri_crg_205.bits.pvr_tsi4_cken    = 0;
    peri_crg_205.bits.pvr_tsi5_cken    = 0;
    peri_crg_205.bits.pvr_tsi6_cken    = 0;
    peri_crg_205.bits.pvr_tsi7_cken    = 0;
    peri_crg_205.bits.pvr_tsi8_cken    = 0;
    peri_crg_206.bits.pvr_ts0_cken     = 0;
    peri_crg_206.bits.pvr_tsout0_cken  = 0;
    peri_crg_206.bits.pvr_tsout1_cken  = 0;
    peri_crg_206.bits.dmx_srst_req     = 0;

    dmx_write_reg(DMX_CRG_REGS_IOBASE, DMX_CRG_REGS205_OFFSET, peri_crg_205.u32);
    dmx_write_reg(DMX_CRG_REGS_IOBASE, DMX_CRG_REGS206_OFFSET, peri_crg_206.u32);

    peri_crg_207.bits.pvr_ts0_cksel = 0;
    peri_crg_207.bits.pvr_ts1_cksel = 0;

    dmx_write_reg(DMX_CRG_REGS_IOBASE, DMX_CRG_REGS207_OFFSET, peri_crg_207.u32);
}

hi_void tee_dmx_hal_get_rec_ts_cnt(const tee_dmx_mgmt *tee_dmx_mgmt_ptr, hi_u32 rec_id, hi_u64 *ts_cnt)
{
    hi_u64 ts_cnt_low;
    hi_u64 ts_cnt_high;

    if (rec_id < 0x6) {
        ts_cnt_low = dmx_read_reg(tee_dmx_mgmt_ptr->io_base, ts_cnt0_5_l(rec_id));
        ts_cnt_high = dmx_read_reg(tee_dmx_mgmt_ptr->io_base, ts_cnt0_5_h(rec_id)) & 0xff;
    } else {
        ts_cnt_low = dmx_read_reg(tee_dmx_mgmt_ptr->io_base, ts_cnt6_31_l(rec_id - 0x6));
        ts_cnt_high = dmx_read_reg(tee_dmx_mgmt_ptr->io_base, ts_cnt6_31_h(rec_id - 0x6)) & 0xff;
    }

    *ts_cnt = ts_cnt_low | (ts_cnt_high << 32); /* left shift 32 bits */
}

#ifdef DMX_SMMU_SUPPORT
hi_void tee_dmx_hal_en_mmu(tee_dmx_mgmt *mgmt)
{
    hi_s32 ret;
    hi_u32 i = 0;
    U_SEC_MMU_EN sec_mmu_en;

    hi_u64 cb_ttbr = 0;
    hi_u64 err_rd_addr = 0;
    hi_u64 err_wr_addr = 0;

    ret = hi_tee_drv_smmu_get_pgtinfo(&err_rd_addr, &err_wr_addr, &cb_ttbr);
    if (ret != HI_SUCCESS) {
        hi_tee_drv_hal_printf("hi_tee_drv_smmu_get_pgtinfo failed!\n");
    }

    mgmt->cb_ttbr = cb_ttbr;
    /* hw restrict cb_ttbr must be 16bytes align. */
    dmx_err_condition_void(cb_ttbr % 16);

    /* configure the mmu page table base register */
    dmx_write_reg_dav(mgmt->io_base, MMU_SEC_TLB, cb_ttbr >> 0x4); /* must 16 byte align */
    dmx_write_reg_dav(mgmt->io_base, MMU_SEC_EADDR, (hi_u32)(err_wr_addr & 0xFFFFFFFFU));
    dmx_write_reg_dav(mgmt->io_base, MMU_R_SEC_EADDR, (hi_u32)(err_rd_addr & 0xFFFFFFFFU));
    dmx_write_reg_dav(mgmt->io_base, MMU_SEC_EADDR_SESSION, (hi_u32)((err_wr_addr >> 32) & 0xFU)); /* shift 32 */
    dmx_write_reg_dav(mgmt->io_base, MMU_R_SEC_EADDR_SESSION, (hi_u32)((err_rd_addr >> 32) & 0xFU)); /* shift 32 */

    sec_mmu_en.u32 = dmx_read_reg_dav(mgmt->io_base, SEC_MMU_EN);
    sec_mmu_en.bits.sec_mmu_en = 1;

    dmx_write_reg_dav(mgmt->io_base, SEC_MMU_EN, sec_mmu_en.u32);

    dmx_com_equal(sec_mmu_en.u32, dmx_read_reg_dav(mgmt->io_base, SEC_MMU_EN));

    /* clear the play rec buffer mmu cache, total 1024 buf, (0~31)1024/BITS_PER_REG */
    for (i = 0; i <= BITS_PER_REG - 1; i++) {
        dmx_write_reg_buf(mgmt->io_base, mmu_buf_dis(i), 0xFFFFFFFF);
    }

    /* clear the pc read buffer mmu cache, (0~1)two register */
    for (i = 0; i <= 1; i++) {
        dmx_write_reg_buf(mgmt->io_base, mmu_pc_rdis_0(i), 0xFFFFFFFF);
    }

    /* clear the pc write buffer mmu cache, (0~1)two register */
    for (i = 0; i <= 1; i++) {
        dmx_write_reg_buf(mgmt->io_base, mmu_pc_wdis_0(i), 0xFFFFFFFF);
    }

    /* clear the ip buffer mmu cache */
    dmx_write_reg_ram(mgmt->io_base, MMU_IP_DIS, 0xFFFFFFFF);

    /* clear the ip desc mmu cache */
    dmx_write_reg_ram(mgmt->io_base, MMU_IP_DES_DIS, 0xFFFFFFFF);
}

hi_void tee_dmx_hal_dis_mmu(const tee_dmx_mgmt *mgmt)
{
    U_SEC_MMU_EN sec_mmu_en;

    sec_mmu_en.u32 = dmx_read_reg_dav(mgmt->io_base, SEC_MMU_EN);
    sec_mmu_en.bits.sec_mmu_en = 0;

    dmx_write_reg_dav(mgmt->io_base, SEC_MMU_EN, sec_mmu_en.u32);

    dmx_com_equal(sec_mmu_en.u32, dmx_read_reg_dav(mgmt->io_base, SEC_MMU_EN));
}

hi_void tee_dmx_hal_buf_clr_mmu_cache(const tee_dmx_mgmt *mgmt, hi_u32 id)
{
    hi_u32 reg_index;
    hi_u32 bit_offset;
    hi_u32 reg;

    dmx_err_condition_void(id >= mgmt->buf_cnt);

    reg_index  = id / BITS_PER_REG;
    bit_offset = id % BITS_PER_REG;

    reg = (1U << bit_offset);

    dmx_write_reg_buf(mgmt->io_base, mmu_buf_dis(reg_index), reg);
}

hi_void tee_dmx_hal_pidcopy_clr_mmu_cache(const tee_dmx_mgmt *mgmt, hi_u32 pcid)
{
    hi_u32 reg_index;
    hi_u32 bit_offset;
    hi_u32 reg;

    dmx_err_condition_void(pcid >= mgmt->dmx_pid_copy_cnt);

    reg_index  = pcid / BITS_PER_REG;
    bit_offset = pcid % BITS_PER_REG;

    reg = (1U << bit_offset);

    dmx_write_reg_buf(mgmt->io_base, mmu_pc_rdis_0(reg_index), reg);
    dmx_write_reg_buf(mgmt->io_base, mmu_pc_wdis_0(reg_index), reg);
}

hi_void tee_dmx_hal_ram_clr_mmu_cache(const tee_dmx_mgmt *mgmt, hi_u32 id)
{
    hi_u32 bit_offset;
    hi_u32 reg;

    dmx_err_condition_void(id >= mgmt->ramport_cnt);

    bit_offset = id % BITS_PER_REG;

    reg = (1U << bit_offset);

    dmx_write_reg_ram(mgmt->io_base, MMU_IP_DIS, reg);
    dmx_write_reg_ram(mgmt->io_base, MMU_IP_DES_DIS, reg);
}
#endif

hi_void tee_dmx_hal_buf_lock_tee_rd(const tee_dmx_mgmt *mgmt, hi_bool lock)
{
    U_DAV_TEE_RD_LOCK tee_rd_lock;

    tee_rd_lock.u32 = dmx_read_reg_dav(mgmt->io_base, DAV_TEE_RD_LOCK);

    if (lock == HI_TRUE) {
        tee_rd_lock.bits.dav_tee_rd_lock = 0x1;
    } else {
        tee_rd_lock.bits.dav_tee_rd_lock = 0x0;
    }

    dmx_write_reg_dav(mgmt->io_base, DAV_TEE_RD_LOCK, tee_rd_lock.u32);

    dmx_com_equal(tee_rd_lock.u32, dmx_read_reg_dav(mgmt->io_base, DAV_TEE_RD_LOCK));

    return;
}

hi_void tee_dmx_hal_ram_port_set_desc(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u64 dsc_phy_addr, hi_u32 dsc_depth)
{
    U_IP_FQ_BUF ip_fq_buf;
    U_IP_FQ_SESSION ip_fq_session;

    dmx_err_condition_void(id >= mgmt->ramport_cnt);

    ip_fq_buf.u32 = dmx_read_reg_ram(mgmt->io_base, ip_fq_buf(id));

    ip_fq_buf.bits.ip_fqsa = (dsc_phy_addr & 0xFFFFFFFF) >> 12; /* 12 for 4k align  */
    ip_fq_buf.bits.ip_fqsize = dsc_depth - 1;   /* hw rule: -1. */
    dmx_write_reg_ram(mgmt->io_base, ip_fq_buf(id), ip_fq_buf.u32);
    dmx_com_equal(ip_fq_buf.u32, dmx_read_reg_ram(mgmt->io_base, ip_fq_buf(id)));

    ip_fq_session.u32 = dmx_read_reg_ram(mgmt->io_base, ip_fq_session(id));
    ip_fq_session.bits.ip_fq_session = (dsc_phy_addr >> 32) & 0xF; /* 32 for high 4 bit */
    dmx_write_reg_ram(mgmt->io_base, ip_fq_session(id), ip_fq_session.u32);

    dmx_com_equal(ip_fq_session.u32, dmx_read_reg_ram(mgmt->io_base, ip_fq_session(id)));
}

hi_void tee_dmx_hal_ram_set_sec_attrs(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool secure)
{
    U_IP_SEC_ATTR ip_set;

    dmx_err_condition_void(id >= mgmt->ramport_cnt);

    ip_set.u32 = dmx_read_reg_ram(mgmt->io_base, IP_SEC_ATTR);

    if (secure == HI_TRUE) {
        ip_set.u32 &= ~(1U << id);
    } else {
        ip_set.u32 |= 1U << id;
    }

    dmx_write_reg_ram(mgmt->io_base, IP_SEC_ATTR, ip_set.u32);
    dmx_com_equal(ip_set.u32, dmx_read_reg_ram(mgmt->io_base, IP_SEC_ATTR));
}

hi_void tee_dmx_hal_buf_set_sec_attrs(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool lock_en, hi_bool secure)
{
    U_BUF_SET buf_set;

    dmx_err_condition_void(id >= mgmt->buf_cnt);

    buf_set.u32 = dmx_read_reg_buf(mgmt->io_base, buf_set(id));

    if (lock_en == HI_TRUE) {
        buf_set.bits.buf_lock     = 0x1;   /* lock */
        dmx_write_reg_buf(mgmt->io_base, buf_set(id), buf_set.u32);
    } else {
        buf_set.bits.buf_lock     = 0x0;   /* unlock */
        dmx_write_reg_buf(mgmt->io_base, buf_set(id), buf_set.u32);
    }

    if (secure == HI_TRUE) {
        buf_set.bits.buf_sec_attr = 0x5;   /* secure */
        dmx_write_reg_buf(mgmt->io_base, buf_set(id), buf_set.u32);
    } else {
        buf_set.bits.buf_sec_attr = 0xA;   /* non secure */
        dmx_write_reg_buf(mgmt->io_base, buf_set(id), buf_set.u32);
    }

    dmx_com_equal(buf_set.u32, dmx_read_reg_buf(mgmt->io_base, buf_set(id)));
}


hi_void tee_dmx_hal_buf_set_start_addr(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u64 start_addr)
{
    U_BUFSA buf_saddr;

    dmx_err_condition_void(id >= mgmt->buf_cnt);

    buf_saddr.u32 = dmx_read_reg_buf(mgmt->io_base, buf_sa(id));
    buf_saddr.bits.buf_session = (start_addr >> 32) & 0xF; /* 32 bits */
    buf_saddr.bits.bufsa = (start_addr & 0xFFFFFFFF) >> 12; /* 12 for 4k align */

    dmx_write_reg_buf(mgmt->io_base, buf_sa(id), buf_saddr.u32);

    dmx_com_equal(buf_saddr.u32, dmx_read_reg_buf(mgmt->io_base, buf_sa(id)));
}

hi_void tee_dmx_hal_buf_set_size(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 buf_size)
{
    U_BUFSIZE rbuf_size;

    dmx_err_condition_void(id >= mgmt->buf_cnt);

    rbuf_size.u32 = dmx_read_reg_buf(mgmt->io_base, buf_size(id));

    rbuf_size.bits.bufsize = (buf_size >> 12) - 1; /* 12: 4k align , hw rule: -1. */

    dmx_write_reg_buf(mgmt->io_base, buf_size(id), rbuf_size.u32);

    dmx_com_equal(rbuf_size.u32, dmx_read_reg_buf(mgmt->io_base, buf_size(id)));
}

hi_void tee_dmx_hal_buf_set_read_idx(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 read_idx)
{
    U_BUFRPTR buf_rptr;

    dmx_err_condition_void(id >= mgmt->buf_cnt);

    buf_rptr.u32 = dmx_read_reg_buf(mgmt->io_base, buf_rptr(id));

    buf_rptr.bits.bufrptr = read_idx;

    dmx_write_reg_buf(mgmt->io_base, buf_rptr(id), buf_rptr.u32);

    dmx_com_equal(buf_rptr.u32, dmx_read_reg_buf(mgmt->io_base, buf_rptr(id)));
}

hi_void tee_dmx_hal_buf_config(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u64 buf_start_addr, hi_u32 buf_size)
{
    /* configure the secure attr */
    tee_dmx_hal_buf_set_sec_attrs(mgmt, id, HI_TRUE, HI_TRUE);

    /* configure the buffer start address */
    tee_dmx_hal_buf_set_start_addr(mgmt, id, buf_start_addr);

    /* configure the buffer size */
    tee_dmx_hal_buf_set_size(mgmt, id, buf_size);

    /* configure the read index */
    tee_dmx_hal_buf_set_read_idx(mgmt, id, 0);
}

hi_void tee_dmx_hal_buf_deconfig(const tee_dmx_mgmt *mgmt, hi_u32 id)
{
    /* configure the buffer start address */
    tee_dmx_hal_buf_set_start_addr(mgmt, id, 0);

    /* configure the buffer size */
    tee_dmx_hal_buf_set_size(mgmt, id, 0);

    /* configure the read index */
    tee_dmx_hal_buf_set_read_idx(mgmt, id, 0);

    /* configure the secure attr */
    tee_dmx_hal_buf_set_sec_attrs(mgmt, id, HI_FALSE, HI_FALSE);
}

/* pidch begin */
hi_void tee_dmx_hal_pid_tab_flt_en(const tee_dmx_mgmt *mgmt, hi_u32 id)
{
    U_PID_TAB_FILTER reg;
    dmx_err_condition_void(id >= mgmt->dmx_raw_pidch_cnt);

    reg.u32 = dmx_read_reg_par(mgmt->io_base, pid_tab_filter(id));
    reg.bits.pid_tab_en = 0x1;

    dmx_write_reg_par(mgmt->io_base, pid_tab_filter(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_par(mgmt->io_base, pid_tab_filter(id)));
}

hi_void tee_dmx_hal_pid_tab_flt_dis(const tee_dmx_mgmt *mgmt, hi_u32 id)
{
    U_PID_TAB_FILTER reg;
    dmx_err_condition_void(id >= mgmt->dmx_raw_pidch_cnt);

    reg.u32 = dmx_read_reg_par(mgmt->io_base, pid_tab_filter(id));
    reg.bits.pid_tab_en = 0x0;

    dmx_write_reg_par(mgmt->io_base, pid_tab_filter(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_par(mgmt->io_base, pid_tab_filter(id)));
}

hi_bool tee_dmx_hal_pid_tab_flt_check(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 dmx_id, hi_u32 pid)
{
    U_PID_TAB_FILTER reg;
    if (id >= mgmt->dmx_raw_pidch_cnt) {
        hi_log_err("id(%u) > raw_pidch_cnt(%u)\n", id, mgmt->dmx_raw_pidch_cnt);
        return HI_FALSE;
    }

    reg.u32 = dmx_read_reg_par(mgmt->io_base, pid_tab_filter(id));

    if (reg.bits.pid_tab_en == 0x1 && reg.bits.dmx_id == dmx_id && reg.bits.pid == pid) {
        return HI_TRUE;
    }
    return HI_FALSE;
}

hi_void tee_dmx_hal_pid_tab_ctl_en_set(const tee_dmx_mgmt *mgmt, hi_u32 id, enum dmx_pid_chn_flag ch_type)
{
    U_PID_TAB_CTRL reg;
    dmx_err_condition_void(id >= mgmt->dmx_raw_pidch_cnt);

    reg.u32 = dmx_read_reg_par(mgmt->io_base, PID_TAB_CTRL(id));

    /* tee lock, only tee cpu config the register */
    reg.bits.pid_head_lock = 0x1;

    reg.u32 |= ch_type;

    dmx_write_reg_par(mgmt->io_base, PID_TAB_CTRL(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_par(mgmt->io_base, PID_TAB_CTRL(id)));
}

static hi_void _dmx_hal_flt_un_lock(const tee_dmx_mgmt *mgmt)
{
    /* configure the flt pes section id */
    u_dmx_pes_sec_id reg;

    /* unlock the bit */
    reg.u32 = dmx_read_reg_flt(mgmt->io_base, DMX_PES_SEC_ID);

    reg.bits.pes_sec_id_lock = 0;

    dmx_write_reg_flt(mgmt->io_base, DMX_PES_SEC_ID, reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_flt(mgmt->io_base, DMX_PES_SEC_ID));
}

static hi_void _dmx_hal_flt_lock(const tee_dmx_mgmt *mgmt)
{
    u_dmx_pes_sec_id reg;

    /* lock the bit */
    reg.u32 = dmx_read_reg_flt(mgmt->io_base, DMX_PES_SEC_ID);

    reg.bits.pes_sec_id_lock = 1;

    dmx_write_reg_flt(mgmt->io_base, DMX_PES_SEC_ID, reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_flt(mgmt->io_base, DMX_PES_SEC_ID));
}

static hi_void _dmx_hal_flt_set_pes_sec_id(const tee_dmx_mgmt *mgmt, hi_u32 pes_sec_id)
{
    u_dmx_pes_sec_id reg;

    reg.u32 = dmx_read_reg_flt(mgmt->io_base, DMX_PES_SEC_ID);

    /* configure the flt pes section id */
    reg.bits.pes_sec_id = pes_sec_id;

    dmx_write_reg_flt(mgmt->io_base, DMX_PES_SEC_ID, reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_flt(mgmt->io_base, DMX_PES_SEC_ID));
}

static hi_void _dmx_hal_flt_set_flt_id(const tee_dmx_mgmt *mgmt, hi_u32 index, hi_u32 flt_id)
{
    u_dmx_filter_id reg;

    reg.u32 = dmx_read_reg_flt(mgmt->io_base, dmx_filter_id(index));

    reg.bits.fit_id = flt_id;

    dmx_write_reg_flt(mgmt->io_base, dmx_filter_id(index), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_flt(mgmt->io_base, dmx_filter_id(index)));
}

static hi_void _dmx_hal_flt_set_ctl_crc(const tee_dmx_mgmt *mgmt, dmx_flt_crc_mode crc_mode)
{
    u_dmx_filter_ctrl reg;

    reg.u32 = dmx_read_reg_flt(mgmt->io_base, DMX_FILTER_CTRL);

    reg.bits.crc_mode = crc_mode;

    dmx_write_reg_flt(mgmt->io_base, DMX_FILTER_CTRL, reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_flt(mgmt->io_base, DMX_FILTER_CTRL));
}

static hi_void _dmx_hal_flt_enable(const tee_dmx_mgmt *mgmt, hi_u32 id)
{
    hi_u32 reg;

    reg = dmx_read_reg_flt(mgmt->io_base, DMX_FILTER_EN);

    reg |= 1 << id;

    dmx_write_reg_flt(mgmt->io_base, DMX_FILTER_EN, reg);

    dmx_com_equal(reg, dmx_read_reg_flt(mgmt->io_base, DMX_FILTER_EN));
}

static hi_void _dmx_hal_flt_disable(const tee_dmx_mgmt *mgmt, hi_u32 id)
{
    hi_u32 reg;

    reg = dmx_read_reg_flt(mgmt->io_base, DMX_FILTER_EN);

    reg &= ~(1 << id);
    dmx_write_reg_flt(mgmt->io_base, DMX_FILTER_EN, reg);

    dmx_com_equal(reg, dmx_read_reg_flt(mgmt->io_base, DMX_FILTER_EN));
}

static hi_void _dmx_hal_flt_set_ctl_attrs(const tee_dmx_mgmt *mgmt, hi_u32 flt_min, hi_u32 flt_num,
    hi_bool err_pes_drop)
{
    u_dmx_filter_ctrl reg;

    reg.u32 = dmx_read_reg_flt(mgmt->io_base, DMX_FILTER_CTRL);

    reg.bits.flt_min              = flt_min;
    reg.bits.flt_num              = flt_num;
    reg.bits.pes_len_err_drop_dis = err_pes_drop;

    dmx_write_reg_flt(mgmt->io_base, DMX_FILTER_CTRL, reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_flt(mgmt->io_base, DMX_FILTER_CTRL));
}

static hi_void _dmx_hal_flt_set_buf_id(const tee_dmx_mgmt *mgmt, hi_u32 buf_id)
{
    u_dmx_filter_buf_id reg;

    reg.u32 = dmx_read_reg_flt(mgmt->io_base, DMX_FILTER_BUF_ID);
    /* set the buf_id */
    reg.bits.flt_buf_id = buf_id;

    dmx_write_reg_flt(mgmt->io_base, DMX_FILTER_BUF_ID, reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_flt(mgmt->io_base, DMX_FILTER_BUF_ID));
}

static hi_void _dmx_hal_flt_pes_sec_set_tee_lock(const tee_dmx_mgmt *mgmt, hi_bool lock_en)
{
    u_dmx_filter_ctrl reg;

    /* configure */
    reg.u32 = dmx_read_reg_flt(mgmt->io_base, DMX_FILTER_CTRL);

    reg.bits.flt_pes_sec_lock = (lock_en == HI_TRUE) ? 1 : 0;

    hi_log_dbg("set flt_pes_sec_lock, reg.u32: 0x%x\n", reg.u32);
    dmx_write_reg_flt(mgmt->io_base, DMX_FILTER_CTRL, reg.u32);
    dmx_com_equal(reg.u32, dmx_read_reg_flt(mgmt->io_base, DMX_FILTER_CTRL));
}

hi_void tee_dmx_hal_flt_pes_sec_config(const tee_dmx_mgmt *mgmt, const dmx_tee_flt_info *flt_info)
{
    _dmx_hal_flt_un_lock(mgmt);

    _dmx_hal_flt_set_pes_sec_id(mgmt, flt_info->pes_sec_id);

    _dmx_hal_flt_lock(mgmt);

    _dmx_hal_flt_pes_sec_set_tee_lock(mgmt, flt_info->flt_pes_sec_lock);
    if (flt_info->flt_pes_sec_lock == HI_TRUE) {
        _dmx_hal_flt_set_flt_id(mgmt, flt_info->flt_index, flt_info->flt_id);

        _dmx_hal_flt_set_ctl_crc(mgmt, flt_info->crc_mode);

        _dmx_hal_flt_enable(mgmt, flt_info->flt_index);

        if (flt_info->status == DMX_FLT_ATTR_INIT) {
            _dmx_hal_flt_un_lock(mgmt);

            _dmx_hal_flt_set_pes_sec_id(mgmt, flt_info->pes_sec_id);

            _dmx_hal_flt_lock(mgmt);

            _dmx_hal_flt_set_ctl_attrs(mgmt, 0, flt_info->flt_num, HI_TRUE);
        }
    } else {
        _dmx_hal_flt_disable(mgmt, flt_info->flt_index);

        _dmx_hal_flt_set_flt_id(mgmt, flt_info->flt_index, 0);
    }

    return;
}

static hi_void _dmx_hal_flt_set_no_flt_mod(const tee_dmx_mgmt *mgmt, hi_bool is_drop)
{
    u_dmx_filter_ctrl reg;

    reg.u32 = dmx_read_reg_flt(mgmt->io_base, DMX_FILTER_CTRL);

    reg.bits.flt_min              = 0;
    reg.bits.flt_num              = 1;
    reg.bits.no_flt_mode          = is_drop;

    dmx_write_reg_flt(mgmt->io_base, DMX_FILTER_CTRL, reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_flt(mgmt->io_base, DMX_FILTER_CTRL));
}

static hi_void _dmx_hal_flt_disable_all_flt(const tee_dmx_mgmt *mgmt)
{
    hi_u32 reg;

    reg = dmx_read_reg_flt(mgmt->io_base, DMX_FILTER_EN);

    reg = 0;
    dmx_write_reg_flt(mgmt->io_base, DMX_FILTER_EN, reg);

    dmx_com_equal(reg, dmx_read_reg_flt(mgmt->io_base, DMX_FILTER_EN));
}

static hi_void _dmx_hal_flt_set_sec_no_pusi(const tee_dmx_mgmt *mgmt, hi_bool no_pusi)
{
    u_dmx_sec_global_ctrl reg;

    reg.u32 = dmx_read_reg_flt(mgmt->io_base, DMX_SEC_GLOBAL_CTRL);
    reg.bits.new_sec_nopusi = no_pusi;
    reg.bits.new_sec_pusi_point = no_pusi;
    reg.bits.new_sec_pusi_nopint = no_pusi;
    dmx_write_reg_flt(mgmt->io_base, DMX_SEC_GLOBAL_CTRL, reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_flt(mgmt->io_base, DMX_SEC_GLOBAL_CTRL));
}

hi_void tee_dmx_hal_flt_set_sec_default_attr(const tee_dmx_mgmt *mgmt, hi_u32 pes_sec_id, hi_u32 buf_id)
{
    /* attention: here must the sequence: unlock->set pessecid->lock */
    /* unlock the flt */
    _dmx_hal_flt_un_lock(mgmt);
    /* configure the pessec channel */
    _dmx_hal_flt_set_pes_sec_id(mgmt, pes_sec_id);
    /* lock the flt */
    _dmx_hal_flt_lock(mgmt);

    /* set the ctl register  */
    _dmx_hal_flt_set_no_flt_mod(mgmt, HI_TRUE);
    _dmx_hal_flt_set_buf_id(mgmt, buf_id);
    _dmx_hal_flt_disable_all_flt(mgmt);

    /* set the default no_pusi attr */
    _dmx_hal_flt_set_sec_no_pusi(mgmt, HI_TRUE);
}

hi_void tee_dmx_hal_flt_set_pes_default_attr(const tee_dmx_mgmt *mgmt, hi_u32 pes_sec_id, hi_u32 buf_id)
{
    /* attention: here must the sequence: unlock->set pessecid->lock */
    /* unlock the flt */
    _dmx_hal_flt_un_lock(mgmt);
    /* configure the pessec channel */
    _dmx_hal_flt_set_pes_sec_id(mgmt, pes_sec_id);
    /* lock the flt */
    _dmx_hal_flt_lock(mgmt);

    /* set the ctl register */
    _dmx_hal_flt_set_no_flt_mod(mgmt, HI_FALSE);
    _dmx_hal_flt_set_buf_id(mgmt, buf_id);
    _dmx_hal_flt_disable_all_flt(mgmt);
}

hi_void tee_dmx_hal_pid_tab_set_cc_drop(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool ccerr_drop, hi_bool ccrepeat_drop)
{
    u_pid_tab_sub_id reg;

    reg.u32 = dmx_read_reg_par(mgmt->io_base, pid_tab_sub_id(id));
    reg.bits.cc_err_drop = ccerr_drop ? 1 : 0;
    reg.bits.cc_repeat_drop = ccrepeat_drop ? 1 : 0;

    dmx_write_reg_par(mgmt->io_base, pid_tab_sub_id(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_par(mgmt->io_base, pid_tab_sub_id(id)));
}

hi_void tee_dmx_hal_pid_tab_ctl_dis_set(const tee_dmx_mgmt *mgmt, hi_u32 id, enum dmx_pid_chn_flag ch_type)
{
    U_PID_TAB_CTRL reg;
    dmx_err_condition_void(id >= mgmt->dmx_raw_pidch_cnt);

    reg.u32 = dmx_read_reg_par(mgmt->io_base, PID_TAB_CTRL(id));
    reg.u32 &= ~ch_type;

    reg.bits.pid_head_lock = 0x0;

    dmx_write_reg_par(mgmt->io_base, PID_TAB_CTRL(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_par(mgmt->io_base, PID_TAB_CTRL(id)));
}

hi_void tee_dmx_hal_pid_tab_set_sub_play_chan_id(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 sub_play_chan_id)
{
    U_PID_TAB_SUB_ID reg;

    dmx_err_condition_void(id >= mgmt->dmx_raw_pidch_cnt);

    reg.u32 = dmx_read_reg_par(mgmt->io_base, PID_TAB_SUB_ID(id));
    reg.bits.whole_sec_av_id = sub_play_chan_id;

    dmx_write_reg_par(mgmt->io_base, PID_TAB_SUB_ID(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_par(mgmt->io_base, PID_TAB_SUB_ID(id)));
}

hi_void tee_dmx_hal_pid_set_whole_tstab(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 buf_id, hi_bool no_afcheck,
    hi_bool tee_lock)
{
    U_WHOLE_TS_TAB reg;

    dmx_err_condition_void(id >= mgmt->play_ts_cnt);

    reg.u32 = dmx_read_reg_par(mgmt->io_base, WHOLE_TS_TAB(id));
    /* configure the whole ts tee lock first */
    if (tee_lock == HI_TRUE) {
        reg.bits.whole_ts_lock = 0x1;
    } else {
        reg.bits.whole_ts_lock = 0x0;
    }

    dmx_write_reg_par(mgmt->io_base, WHOLE_TS_TAB(id), reg.u32);

    reg.bits.whole_ts_buf_id = buf_id;
    reg.bits.whole_af_check_dis = no_afcheck;

    dmx_write_reg_par(mgmt->io_base, WHOLE_TS_TAB(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_par(mgmt->io_base, WHOLE_TS_TAB(id)));
}

hi_void tee_dmx_hal_pid_set_av_pes_tab(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 buf_id, hi_bool pusi_en,
    hi_bool tee_lock)
{
    U_AV_PES_TAB reg;

    dmx_err_condition_void(id >= mgmt->avr_cnt);

    reg.u32 = dmx_read_reg_par(mgmt->io_base, AV_PES_TAB(id));
    if (tee_lock == HI_TRUE) {
        reg.bits.av_pes_lock = 0x1;
    } else {
        reg.bits.av_pes_lock = 0x0;
    }
    dmx_write_reg_par(mgmt->io_base, AV_PES_TAB(id), reg.u32);

    reg.bits.av_pes_buf_id = buf_id;
    reg.bits.av_pusi_en = pusi_en;
    reg.bits.flt_rec_sel = DMX_PID_TYPE_REC_SCD;
    /* disable the pes head len check */
    reg.bits.av_pes_len_det = 0x0;

    dmx_write_reg_par(mgmt->io_base, AV_PES_TAB(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_par(mgmt->io_base, AV_PES_TAB(id)));
}

hi_void tee_dmx_hal_pid_set_rec_dsc_mode(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool descramed)
{
    U_PID_TAB_SUB_ID reg;

    dmx_err_condition_void(id >= mgmt->dmx_raw_pidch_cnt);

    reg.u32 = dmx_read_reg_par(mgmt->io_base, PID_TAB_SUB_ID(id));
    if (descramed == HI_TRUE) {
        reg.bits.dsc_rec_mode = 0x0;  /* record clear stream */
    } else {
        reg.bits.dsc_rec_mode = 0x1;  /* record original scrambled stream */
    }

    dmx_write_reg_par(mgmt->io_base, PID_TAB_SUB_ID(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_par(mgmt->io_base, PID_TAB_SUB_ID(id)));
}

hi_void tee_dmx_hal_pid_set_pes_sec_tab(const tee_dmx_mgmt *mgmt, hi_u32 id, enum dmx_pid_pes_sec_type pes_sec_type,
    hi_bool pusi_en, hi_bool pes_len_chk)
{
    U_PES_SEC_TAB0 reg;

    dmx_err_condition_void(id >= mgmt->play_pes_sec_cnt);

    reg.u32 = dmx_read_reg_par(mgmt->io_base, PES_SEC_TAB0(id));
    reg.bits.pes_sec_lock = 0x1;
    dmx_write_reg_par(mgmt->io_base, PES_SEC_TAB0(id), reg.u32);

    reg.bits.data_type = pes_sec_type;
    reg.bits.pes_sec_pusi_en = pusi_en;
    reg.bits.pes_sec_len_det = pes_len_chk;

    dmx_write_reg_par(mgmt->io_base, PES_SEC_TAB0(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_par(mgmt->io_base, PES_SEC_TAB0(id)));
}

hi_void tee_dmx_hal_pes_sec_unlock(const tee_dmx_mgmt *mgmt, hi_u32 id)
{
    U_PES_SEC_TAB0 reg;

    dmx_err_condition_void(id >= mgmt->play_pes_sec_cnt);

    reg.u32 = dmx_read_reg_par(mgmt->io_base, PES_SEC_TAB0(id));
    reg.bits.pes_sec_lock = 0;
    dmx_write_reg_par(mgmt->io_base, PES_SEC_TAB0(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_par(mgmt->io_base, PES_SEC_TAB0(id)));
}

hi_void tee_dmx_hal_pid_set_rec_tab(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 rec_id)
{
    U_PID_TAB_REC_SCD reg;

    dmx_err_condition_void(id >= mgmt->dmx_raw_pidch_cnt);

    reg.u32 = dmx_read_reg_par(mgmt->io_base, PID_TAB_REC_SCD(id));
    reg.bits.rec_id = rec_id;

    dmx_write_reg_par(mgmt->io_base, PID_TAB_REC_SCD(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_par(mgmt->io_base, PID_TAB_REC_SCD(id)));
}

hi_void tee_dmx_hal_pid_set_scd_tab(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 ts_scd_id, hi_u32 pes_scd_id)
{
    U_PID_TAB_REC_SCD reg;

    dmx_err_condition_void(id >= mgmt->dmx_raw_pidch_cnt);

    reg.u32 = dmx_read_reg_par(mgmt->io_base, PID_TAB_REC_SCD(id));
    reg.bits.pes_scd_id = pes_scd_id;
    reg.bits.scd_id     = ts_scd_id;

    dmx_write_reg_par(mgmt->io_base, PID_TAB_REC_SCD(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_par(mgmt->io_base, PID_TAB_REC_SCD(id)));
}

hi_void tee_dmx_hal_pid_cw_en_set(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool cw_en)
{
    U_PID_TAB_CTRL reg;

    dmx_err_condition_void(id >= mgmt->dmx_raw_pidch_cnt);

    reg.u32 = dmx_read_reg_par(mgmt->io_base, PID_TAB_CTRL(id));
    reg.bits.cw_en = cw_en ? 1 : 0;

    dmx_write_reg_par(mgmt->io_base, PID_TAB_CTRL(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_par(mgmt->io_base, PID_TAB_CTRL(id)));
}

hi_bool tee_dmx_hal_pid_cw_en_check(const tee_dmx_mgmt *mgmt, hi_u32 id)
{
    U_PID_TAB_CTRL reg;

    if (id >= mgmt->dmx_raw_pidch_cnt) {
        hi_log_err("id(%u) > raw_pidch_cnt(%u)\n", id, mgmt->dmx_raw_pidch_cnt);
        return HI_FALSE;
    }

    reg.u32 = dmx_read_reg_par(mgmt->io_base, PID_TAB_CTRL(id));
    if (reg.bits.cw_en == 1) {
        return HI_TRUE;
    }

    return HI_FALSE;
}

hi_void tee_dmx_hal_pid_set_cw_id(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 cw_id)
{
    U_PID_TAB_SUB_ID reg;

    dmx_err_condition_void(id >= mgmt->dmx_raw_pidch_cnt);

    reg.u32 = dmx_read_reg_par(mgmt->io_base, PID_TAB_SUB_ID(id));
    reg.bits.cw_id = cw_id;

    dmx_write_reg_par(mgmt->io_base, PID_TAB_SUB_ID(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_par(mgmt->io_base, PID_TAB_SUB_ID(id)));
}

hi_void tee_dmx_hal_pid_get_cw_id(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 *cw_id)
{
    U_PID_TAB_SUB_ID reg;

    dmx_err_condition_void(id >= mgmt->dmx_raw_pidch_cnt);

    reg.u32 = dmx_read_reg_par(mgmt->io_base, PID_TAB_SUB_ID(id));
    *cw_id = reg.bits.cw_id;
}

hi_void tee_dmx_hal_pid_set_dsc_type(const tee_dmx_mgmt *mgmt, hi_u32 dsc_id, hi_bool ts_desc_en, hi_bool pes_desc_en)
{
    U_CW_TAB reg;
    hi_u32 offset;

    /* cw 0~127 at address of CW_TAB0(dsc_id),cw 128~255 at address of CW_TAB1(dsc_id) */
    offset = dsc_id > 127 ? CW_TAB1(dsc_id) : CW_TAB0(dsc_id);

    reg.u32 = dmx_read_reg_par(mgmt->io_base, offset);
    reg.bits.ts_descram = ts_desc_en ? 1 : 0;
    reg.bits.pes_descram = pes_desc_en ? 1 : 0;

    dmx_write_reg_par(mgmt->io_base, CW_TAB0(dsc_id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_par(mgmt->io_base, offset));
}

/* scd begin */
hi_void tee_dmx_hal_scd_en(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool scd_en)
{
    u_scd_cfg_h32 reg;

    dmx_err_condition_void(id >= mgmt->dmx_scd_cnt);

    reg.u32 = dmx_read_reg_scd(mgmt->io_base, ts_scd_cfg_h32(id));

    reg.bits.scd_chn_en = scd_en ? 1 : 0;

    dmx_write_reg_scd(mgmt->io_base, ts_scd_cfg_h32(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_scd(mgmt->io_base, ts_scd_cfg_h32(id)));
}

hi_void tee_dmx_hal_scd_set_buf_id(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 buf_id)
{
    u_scd_cfg_h32 reg;

    dmx_err_condition_void(id >= mgmt->dmx_scd_cnt);

    reg.u32 = dmx_read_reg_scd(mgmt->io_base, ts_scd_cfg_h32(id));

    reg.bits.ts_scd_bufid    = buf_id;

    dmx_write_reg_scd(mgmt->io_base, ts_scd_cfg_h32(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_scd(mgmt->io_base, ts_scd_cfg_h32(id)));
}

hi_void tee_dmx_hal_scd_set_tee_lock(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool lock_en)
{
    u_scd_cfg_h32 reg;
    dmx_err_condition_void(id >= mgmt->dmx_scd_cnt);

    /* configure */
    reg.u32 = dmx_read_reg_scd(mgmt->io_base, ts_scd_cfg_h32(id));

    reg.bits.scd_tee_lock = lock_en;

    dmx_write_reg_scd(mgmt->io_base, ts_scd_cfg_h32(id), reg.u32);
    dmx_com_equal(reg.u32, dmx_read_reg_scd(mgmt->io_base, ts_scd_cfg_h32(id)));
}

hi_void tee_dmx_hal_scd_set_rec_tab(const tee_dmx_mgmt *mgmt, hi_u32 id,
    hi_bool tpit_en, hi_bool pes_en, hi_bool es_long_en)
{
    u_scd_cfg_h32 reg;

    dmx_err_condition_void(id >= mgmt->dmx_scd_cnt);

    reg.u32 = dmx_read_reg_scd(mgmt->io_base, ts_scd_cfg_h32(id));

    reg.bits.idx_mode        = 0x0; /* rec index mode */
    reg.bits.scd_tpit_en     = tpit_en ? 1 : 0;
    reg.bits.scd_pes_en      = pes_en ? 1 : 0;
    reg.bits.scd_es_long_en  = es_long_en ? 1 : 0;
    reg.bits.scd_es_short_en = 0;

    dmx_write_reg_scd(mgmt->io_base, ts_scd_cfg_h32(id), reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_scd(mgmt->io_base, ts_scd_cfg_h32(id)));
}

hi_void tee_dmx_hal_scd_set_flt_en(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool flt_en)
{
    u_scd_cfg_h32 reg;
    hi_u32 reg_value = 0;

    dmx_err_condition_void(id >= mgmt->dmx_scd_cnt);

    reg.u32 = dmx_read_reg_scd(mgmt->io_base, ts_scd_cfg_h32(id));

    if (flt_en == HI_TRUE) {
        reg.bits.scd_flth_en = 0xFF;
        reg_value  = 0xFFFFFFFF;
    } else {
        reg.bits.scd_flth_en = 0x0;
        reg_value  = 0x0;
    }
    dmx_write_reg_scd(mgmt->io_base, ts_scd_cfg_h32(id), reg.u32);
    dmx_write_reg_scd(mgmt->io_base, ts_scd_cfg_l32(id), reg_value);

    dmx_com_equal(reg.u32, dmx_read_reg_scd(mgmt->io_base, ts_scd_cfg_h32(id)));
    dmx_com_equal(reg_value, dmx_read_reg_scd(mgmt->io_base, ts_scd_cfg_l32(id)));
}

hi_void tee_dmx_hal_scd_set_av_pes_cfg(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_u32 chan_en, hi_u32 mode,
    hi_u32 pesh_id_ena)
{
    U_REC_CFG_H32 reg;

    dmx_err_condition_void(id >= mgmt->dmx_scd_cnt);

    /* configure */
    reg.u32 = dmx_read_reg_scd(mgmt->io_base, TS_REC_CFG_H32(id));

    reg.bits.rec_chn_en = 0;

    dmx_write_reg_scd(mgmt->io_base, TS_REC_CFG_H32(id), reg.u32);

    /* lock & unlock and disable it first */
    if (chan_en == HI_TRUE) {
        reg.bits.chn_tee_lock = 0x1;
    } else {
        reg.bits.chn_tee_lock = 0x0;
    }

    reg.bits.chn_mode  = mode;
    reg.bits.ctrl_mode = 0x0;
    reg.bits.ctrl_edit_dis = 0x0;
    reg.bits.chn_crc_en = 0x0;
    reg.bits.rec_bufid = pesh_id_ena; /* mq enable or not */
    reg.bits.avpes_len_dis = 0x1; /* close the pes len check when avpes channel */
    reg.bits.avpes_cut_dis = 0x1; /* don't drop the pes when pes len invalid */

    dmx_write_reg_scd(mgmt->io_base, TS_REC_CFG_H32(id), reg.u32);
    dmx_com_equal(reg.u32, dmx_read_reg_scd(mgmt->io_base, TS_REC_CFG_H32(id)));

    /* enable & disable */
    reg.u32 = dmx_read_reg_scd(mgmt->io_base, TS_REC_CFG_H32(id));
    reg.bits.rec_chn_en = chan_en == HI_TRUE ? 1 : 0;

    dmx_write_reg_scd(mgmt->io_base, TS_REC_CFG_H32(id), reg.u32);
    /* only compare the bit 31 */
    dmx_com_equal(reg.u32 >> 31U, dmx_read_reg_scd(mgmt->io_base, TS_REC_CFG_H32(id)) >> 31U);
}

hi_void tee_dmx_hal_scd_set_ts_rec_cfg(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool ts_rec_en, hi_u32 buf_id)
{
    U_REC_CFG_H32 reg;

    /* disable */
    reg.u32 = dmx_read_reg_scd(mgmt->io_base, TS_REC_CFG_H32(id));
    reg.bits.rec_chn_en = 0;

    dmx_write_reg_scd(mgmt->io_base, TS_REC_CFG_H32(id), reg.u32);

    reg.u32 = dmx_read_reg_scd(mgmt->io_base, TS_REC_CFG_H32(id));
    /* configure */
    if (ts_rec_en == HI_TRUE) {
        reg.bits.chn_tee_lock = 0x1; /* enable */
    } else {
        reg.bits.chn_tee_lock = 0x0; /* disable */
    }
    reg.bits.chn_mode = 0x0; /* record */
    reg.bits.rec_bufid  = buf_id;

    dmx_write_reg_scd(mgmt->io_base, TS_REC_CFG_H32(id), reg.u32);
    dmx_com_equal(reg.u32, dmx_read_reg_scd(mgmt->io_base, TS_REC_CFG_H32(id)));

    /* enable */
    reg.u32 = dmx_read_reg_scd(mgmt->io_base, TS_REC_CFG_H32(id));
    reg.bits.rec_chn_en = ts_rec_en;

    dmx_write_reg_scd(mgmt->io_base, TS_REC_CFG_H32(id), reg.u32);
    /* only compare the bit 31 */
    dmx_com_equal(reg.u32 >> 31U, dmx_read_reg_scd(mgmt->io_base, TS_REC_CFG_H32(id)) >> 31U);
}

hi_void tee_dmx_hal_rec_chn_enable(const tee_dmx_mgmt *mgmt, hi_u32 id)
{
    tee_dmx_hal_scd_set_ts_rec_cfg(mgmt, id, HI_TRUE, mgmt->rec_info[id].rec_secbuf.buf_id);
}

/* set mdsc iv/cw key even or odd when encrypted */
hi_void tee_dmx_hal_mdscset_encrypt_even_odd(const tee_dmx_mgmt *mgmt, hi_u32 id, dmx_dsc_key_type even_odd)
{
    hi_u32 reg_index;
    hi_u32 bit_offset;
    hi_u32 reg;

    dmx_err_condition_void(id >= mgmt->key_cnt);

    reg_index  = id / BITS_PER_REG;
    bit_offset = id % BITS_PER_REG;

    reg = dmx_read_reg_mdsc(mgmt->io_mdsc_base, KEY_ENCRPTY_SEL(reg_index));

    if (even_odd == DMX_DSC_KEY_ODD) {
        reg |= 1 << bit_offset;
    } else {
        reg &= ~(1 << bit_offset);
    }

    dmx_write_reg_mdsc(mgmt->io_mdsc_base, KEY_ENCRPTY_SEL(reg_index), reg);

    dmx_com_equal(reg, dmx_read_reg_mdsc(mgmt->io_mdsc_base, KEY_ENCRPTY_SEL(reg_index)));
}

/* Set the valid bits of EntropyReduction */
hi_void tee_dmx_hal_mdscset_entropy_reduction(const tee_dmx_mgmt *mgmt, hi_u32 id, dmx_dsc_entropy entropy_reduction)
{
    hi_u32 reg;
    hi_u32 reg_index;
    hi_u32 bit_offset;

    dmx_err_condition_void(id >= mgmt->key_cnt);

    if (id >= 64) { /* CSA2 ENTROPY CLOSE register only support CW [0~64) */
        hi_log_err("Do not support such cw! id = %u\n", id);
        return;
    }

    reg_index  = id / BITS_PER_REG;
    bit_offset = id % BITS_PER_REG;

    reg = dmx_read_reg_mdsc(mgmt->io_mdsc_base, CSA2_ENTROPY_CLOSE(reg_index));
    if (entropy_reduction == DMX_CA_ENTROPY_CLOSE) {
        reg |= 1 << bit_offset;
    } else {
        reg &= ~(1 << bit_offset);
    }

    dmx_write_reg_mdsc(mgmt->io_mdsc_base, CSA2_ENTROPY_CLOSE(reg_index), reg);

    dmx_com_equal(reg, dmx_read_reg_mdsc(mgmt->io_mdsc_base, CSA2_ENTROPY_CLOSE(reg_index)));
}

/* Set the Mdsc Enable register */
hi_void tee_dmx_hal_mdscset_en(const tee_dmx_mgmt *mgmt, hi_bool ca_en, hi_bool ts_ctrl_dsc_change_en, hi_bool cw_iv_en)
{
    U_MDSC_EN reg;

    reg.u32 = dmx_read_reg_mdsc(mgmt->io_mdsc_base, MDSC_EN);

    reg.bits.ca_en                 = ca_en ? 1 : 0;
    reg.bits.ts_ctrl_dsc_change_en = ts_ctrl_dsc_change_en  ? 1 : 0;
    reg.bits.cw_iv_en              = cw_iv_en ? 1 : 0;

    dmx_write_reg_mdsc(mgmt->io_mdsc_base, MDSC_EN, reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_mdsc(mgmt->io_mdsc_base, MDSC_EN));
}

/* The cpd core disable register */
hi_void tee_dmx_hal_mdscdis_cpd_core(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool dis_core)
{
    U_MDSC_CPD_CORE_DISABLE reg;

    dmx_err_condition_void(id >= mgmt->key_cnt);

    reg.u32 = dmx_read_reg_mdsc(mgmt->io_mdsc_base, MDSC_CPD_CORE_DISABLE);

    /* cpd core enable is 8th bit. */
    reg.bits.cpd_core_disable = dis_core ? ~(1 << 0x8) : 0;

    dmx_write_reg_mdsc(mgmt->io_mdsc_base, MDSC_CPD_CORE_DISABLE, reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_mdsc(mgmt->io_mdsc_base, MDSC_CPD_CORE_DISABLE));
}

/* The ca core disable register */
hi_void tee_dmx_hal_mdscdis_ca_core(const tee_dmx_mgmt *mgmt, hi_bool dis_core)
{
    U_MDSC_CA_CORE_DISABLE reg;

    reg.u32 = dmx_read_reg_mdsc(mgmt->io_mdsc_base, MDSC_CA_CORE_DISABLE);

    reg.bits.ca_core_disable = dis_core ? ~(1 << 28) : 0;   /* 28: ca core enable is 0~27th bit. */

    dmx_write_reg_mdsc(mgmt->io_mdsc_base, MDSC_CA_CORE_DISABLE, reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_mdsc(mgmt->io_mdsc_base, MDSC_CA_CORE_DISABLE));
}

/* The cps core disable register */
hi_void tee_dmx_hal_mdscdis_cps_core(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool dis_core)
{
    U_MDSC_CPS_CORE_DISABLE reg;

    dmx_err_condition_void(id >= mgmt->key_cnt);

    reg.u32 = dmx_read_reg_mdsc(mgmt->io_mdsc_base, MDSC_CPS_CORE_DISABLE);

    /* cps core enable is 8th bit. */
    reg.bits.cps_core_disable = dis_core ? ~(1 << 0x8) : 0;

    dmx_write_reg_mdsc(mgmt->io_mdsc_base, MDSC_CPS_CORE_DISABLE, reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_mdsc(mgmt->io_mdsc_base, MDSC_CPS_CORE_DISABLE));
}

hi_void tee_dmx_hal_mdsc_key_slot_sec_cfg(const tee_dmx_mgmt *mgmt, hi_u32 id, hi_bool secure_en)
{
    hi_u32 bit_offset;
    hi_u32 reg = 0;

    dmx_err_condition_void(id >= mgmt->key_cnt);

    bit_offset = id % BITS_PER_REG;

    if (secure_en == HI_TRUE) {
        reg |= 1 << bit_offset;
    } else {
        reg &= ~(1 << bit_offset);
    }

    if (id < 32) {  /* 32:key slot secure config register, cw0~31 */
        dmx_write_reg_mdsc(mgmt->io_mdsc_base, KEY_SLOT_SEC_CFG0, reg);
    } else if (id < 64) {   /* 64:key slot secure config register, cw32~63 */
        dmx_write_reg_mdsc(mgmt->io_mdsc_base, KEY_SLOT_SEC_CFG1, reg);
    } else if (id < 96) {   /* 96:key slot secure config register, cw64~95 */
        dmx_write_reg_mdsc(mgmt->io_mdsc_base, KEY_SLOT_SEC_CFG2, reg);
    } else if (id < 128) {  /* 128:key slot secure config register, cw96~127 */
        dmx_write_reg_mdsc(mgmt->io_mdsc_base, KEY_SLOT_SEC_CFG3, reg);
    } else if (id < 160) {  /* 160:key slot secure config register, cw128~159 */
        dmx_write_reg_mdsc(mgmt->io_mdsc_base, KEY_SLOT_SEC_CFG4, reg);
    } else if (id < 192) {  /* 192:key slot secure config register, cw160~191 */
        dmx_write_reg_mdsc(mgmt->io_mdsc_base, KEY_SLOT_SEC_CFG5, reg);
    } else if (id < 224) {  /* 224:key slot secure config register, cw192~223 */
        dmx_write_reg_mdsc(mgmt->io_mdsc_base, KEY_SLOT_SEC_CFG6, reg);
    } else if (id < 256) {  /* 256:key slot secure config register, cw224~255 */
        dmx_write_reg_mdsc(mgmt->io_mdsc_base, KEY_SLOT_SEC_CFG7, reg);
    } else {
        hi_tee_drv_hal_printf("key slot[%u] secure config failed!\n", id);
    }
}

/* key slot secure config lock register, can only be set by TEE CPU,
 * and can not be set to other value after set to 0x0101 except hardware reset.
 */
hi_void tee_dmx_hal_mdsc_key_slot_sec_cfg_lock(const tee_dmx_mgmt *mgmt, hi_bool secure_lock_en)
{
    U_KEY_SLOT_SEC_CFG_LOCK reg;

    reg.u32 = dmx_read_reg_mdsc(mgmt->io_mdsc_base, KEY_SLOT_SEC_CFG_LOCK);
    if (secure_lock_en == HI_TRUE) {
        /* if value is not 0x5(0101) the key slot secure config register will be locked */
        reg.bits.key_slot_sec_cfg_lock = 0;
    } else {
        /* the value of 0x5(0101) meanse unlock */
        reg.bits.key_slot_sec_cfg_lock = 0x5;
    }

    dmx_write_reg_mdsc(mgmt->io_mdsc_base, KEY_SLOT_SEC_CFG_LOCK, reg.u32);

    dmx_com_equal(reg.u32, dmx_read_reg_mdsc(mgmt->io_mdsc_base, KEY_SLOT_SEC_CFG_LOCK));
}

hi_void tee_dmx_hal_mdsc_multi2_sys_key_cfg(const tee_dmx_mgmt *mgmt, hi_u8 *key, hi_u32 key_len)
{
    /* multi2 system key must be 32 Bytes */
    if (key_len != DMX_SYS_KEY_LEN) {
        hi_log_err("multi2 key len is not correct! key_len=%u Bytes\n", key_len);
        return;
    }
    /* write multi2 sys key0 */
    dmx_write_reg_mdsc(mgmt->io_mdsc_base, MULTI2_SYS_KEY0, *(hi_u32*)key);

    /* write multi2 sys key1 */
    dmx_write_reg_mdsc(mgmt->io_mdsc_base, MULTI2_SYS_KEY1, *(hi_u32*)(key + 4));   /* offset 4 bits */

    /* write multi2 sys key2 */
    dmx_write_reg_mdsc(mgmt->io_mdsc_base, MULTI2_SYS_KEY2, *(hi_u32*)(key + 8));   /* offset 8 bits */

    /* write multi2 sys key3 */
    dmx_write_reg_mdsc(mgmt->io_mdsc_base, MULTI2_SYS_KEY3, *(hi_u32*)(key + 12));  /* offset 12 bits */

    /* write multi2 sys key4 */
    dmx_write_reg_mdsc(mgmt->io_mdsc_base, MULTI2_SYS_KEY4, *(hi_u32*)(key + 16));  /* offset 16 bits */

    /* write multi2 sys key5 */
    dmx_write_reg_mdsc(mgmt->io_mdsc_base, MULTI2_SYS_KEY5, *(hi_u32*)(key + 20));  /* offset 20 bits */

    /* write multi2 sys key6 */
    dmx_write_reg_mdsc(mgmt->io_mdsc_base, MULTI2_SYS_KEY6, *(hi_u32*)(key + 24));  /* offset 24 bits */

    /* write multi2 sys key7 */
    dmx_write_reg_mdsc(mgmt->io_mdsc_base, MULTI2_SYS_KEY7, *(hi_u32*)(key + 28));  /* offset 28 bits */
}

