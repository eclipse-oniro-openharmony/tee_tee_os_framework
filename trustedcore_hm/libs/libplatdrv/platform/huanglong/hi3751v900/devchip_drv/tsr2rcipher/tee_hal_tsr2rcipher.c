/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: tee hal tsr2rcipher impl.
 * Author: sdk
 * Create: 2019-08-02
 */

#include "hi_type_dev.h"

#include "tee_hal_tsr2rcipher.h"
#include "tee_drv_tsr2rcipher_reg.h"
#include "tee_drv_ioctl_tsr2rcipher.h"

#include "hi_tee_drv_mem.h"

#define tsc_fatal_con_void_return(condition) do {                           \
    if ((condition)) {                                                      \
        hi_log_fatal("TSR2RCIPHER FATAL ERROR: %s!\n", #condition); \
        return;                                                             \
    }                                                                       \
} while (0)

#define tsc_condition_return_value(condition, value) do {                           \
    if ((condition)) {                                                      \
        hi_log_fatal("TSR2RCIPHER FATAL ERROR: %s!\n", #condition); \
        return (value);                                                             \
    }                                                                       \
} while (0)

hi_void tee_tsc_hal_init_hw(hi_void)
{
    peri_crg185 peri_crg_185;

    peri_crg_185.u32 = tsc_read_reg(TSC_CRG_REGS_IOBASE, TSC_CRG_REGS185_OFFSET);

    peri_crg_185.bits.tscipher_srst_req = 1;
    tsc_write_reg(TSC_CRG_REGS_IOBASE, TSC_CRG_REGS185_OFFSET, peri_crg_185.u32);

    peri_crg_185.bits.tscipher_cken = 1;
    peri_crg_185.bits.tscipher_srst_req = 0;
    tsc_write_reg(TSC_CRG_REGS_IOBASE, TSC_CRG_REGS185_OFFSET, peri_crg_185.u32);
}

hi_void tee_tsc_hal_deinit_hw(hi_void)
{
    peri_crg185 peri_crg_185;

    peri_crg_185.u32 = tsc_read_reg(TSC_CRG_REGS_IOBASE, TSC_CRG_REGS185_OFFSET);

    peri_crg_185.bits.tscipher_srst_req = 1;
    tsc_write_reg(TSC_CRG_REGS_IOBASE, TSC_CRG_REGS185_OFFSET, peri_crg_185.u32);

    peri_crg_185.bits.tscipher_cken = 0;
    peri_crg_185.bits.tscipher_srst_req = 0;
    tsc_write_reg(TSC_CRG_REGS_IOBASE, TSC_CRG_REGS185_OFFSET, peri_crg_185.u32);
}

#ifdef TSR2RCIPHER_SMMU_SUPPORT
hi_void tee_tsc_hal_en_mmu(tee_tsr2rcipher_mgmt *mgmt)
{
    hi_s32 ret;
    hi_u32 i;
    tsc_mmu_sec_en mmu_sec_en;

    hi_u64 cb_ttbr = 0;
    hi_u64 err_rd_addr = 0;
    hi_u64 err_wr_addr = 0;

    ret = hi_tee_drv_smmu_get_pgtinfo(&err_rd_addr, &err_wr_addr, &cb_ttbr);
    if (ret != HI_SUCCESS) {
        hi_log_err("hi_tee_drv_smmu_get_pgtinfo failed!\n");
        return;
    }

    mgmt->cb_ttbr = cb_ttbr;

    /* hw restrict cb_ttbr must be 16bytes align. */
    tsc_fatal_con_void_return(cb_ttbr % 16);

    /* configure the tlb base addr and waster buffer addr */
    tsc_write_reg_top(mgmt->io_base, TSC_MMU_SEC_TLB, cb_ttbr >> 4); /* shift right 4 bits to get mmu base address */
    tsc_write_reg_top(mgmt->io_base, TSC_MMU_RX_SEC_EADDR_L, (hi_u32)(err_rd_addr & 0xFFFFFFFFU));
    tsc_write_reg_top(mgmt->io_base, TSC_MMU_TX_SEC_EADDR_L, (hi_u32)(err_wr_addr & 0xFFFFFFFFU));
    /* right shift 32 bits to get high 4 bits */
    tsc_write_reg_top(mgmt->io_base, TSC_MMU_RX_SEC_EADDR_H, (hi_u32)((err_rd_addr >> 32) & 0xFU));
    /* right shift 32 bits to get high 4 bits */
    tsc_write_reg_top(mgmt->io_base, TSC_MMU_TX_SEC_EADDR_H, (hi_u32)((err_wr_addr >> 32) & 0xFU));

    mmu_sec_en.u32 = tsc_read_reg_top(mgmt->io_base, TSC_MMU_SEC_EN);
    mmu_sec_en.bits.sw_sec_mmu_en = 1;
    tsc_write_reg_top(mgmt->io_base, TSC_MMU_SEC_EN, mmu_sec_en.u32);

    tsc_com_equal(mmu_sec_en.u32, tsc_read_reg_top(mgmt->io_base, TSC_MMU_SEC_EN));

    for (i = 0; i < 8; i++) { /* cycle 8 times to clear page table */
        tsc_write_reg_top(mgmt->io_base, tsc_mmu_rx_clr(i), 0xFFFFFFFF);
    }

    for (i = 0; i < 8; i++) { /* cycle 8 times to clear page table */
        tsc_write_reg_top(mgmt->io_base, tsc_mmu_tx_clr(i), 0xFFFFFFFF);
    }
}

hi_void tee_tsc_hal_dis_mmu(tee_tsr2rcipher_mgmt *mgmt)
{
    tsc_mmu_sec_en mmu_sec_en;

    mmu_sec_en.u32 = tsc_read_reg_top(mgmt->io_base, TSC_MMU_SEC_EN);
    mmu_sec_en.bits.sw_sec_mmu_en = 0;

    tsc_write_reg_top(mgmt->io_base, TSC_MMU_SEC_EN, mmu_sec_en.u32);

    tsc_com_equal(mmu_sec_en.u32, tsc_read_reg_top(mgmt->io_base, TSC_MMU_SEC_EN));
}
#endif

hi_void tee_tsc_hal_top_set_int(tee_tsr2rcipher_mgmt *mgmt, hi_bool rx_int, hi_bool tx_int, hi_bool cipher_int)
{
    tsc_iena reg;

    reg.u32 = tsc_read_reg_top(mgmt->io_base, TSC_IENA);
    reg.bits.rx2cpu_iena     = (rx_int == HI_TRUE ? 1 : 0);
    reg.bits.tx2cpu_iena     = (tx_int == HI_TRUE ? 1 : 0);
    reg.bits.cipher2cpu_iena = (cipher_int == HI_TRUE ? 1 : 0);

    tsc_write_reg_top(mgmt->io_base, TSC_IENA, reg.u32);

    tsc_com_equal(reg.u32, tsc_read_reg_top(mgmt->io_base, TSC_IENA));
}

hi_void tee_tsc_hal_rx_config(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id, enum tsc_buf_type buf_type)
{
    tsc_rx_ctrl reg;

    tsc_fatal_con_void_return(id >= mgmt->ch_cnt);
    id += TSR2RCIPHER_CH_BASE;

    reg.u32 = tsc_read_reg_rx(mgmt->io_base, tsc_rx_ctrl(id));
    reg.bits.rx_buf_type = buf_type;

    tsc_write_reg_rx(mgmt->io_base, tsc_rx_ctrl(id), reg.u32);

    tsc_com_equal(reg.u32, tsc_read_reg_rx(mgmt->io_base, tsc_rx_ctrl(id)));
}

hi_bool tee_tsc_hal_rx_get_dsptor_status(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id)
{
    rx_dsptor_ctrl reg;

    if (id >= mgmt->ch_cnt) {
        hi_log_err("id is invalid!\n");
        return HI_FALSE;
    }
    id += TSR2RCIPHER_CH_BASE;

    reg.u32 = tsc_read_reg_rx(mgmt->io_base, rx_dsptor_ctrl(id));

    return (reg.bits.rx_dsptor_full == 0x0);
}

hi_void _tee_tsc_hal_rx_set_buf_addr(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id, hi_u64 src_addr)
{
    rx_dsptor_start_addr reg_addr;
    tsc_rx_ctrl reg_ctrl;

    reg_addr.u32 = tsc_read_reg_rx(mgmt->io_base, rx_dsptor_start_addr(id));
    reg_ctrl.u32 = tsc_read_reg_rx(mgmt->io_base, tsc_rx_ctrl(id));

    reg_addr.bits.rx_dsptor_start_addr = src_addr & 0x00000000FFFFFFFF;
    reg_ctrl.bits.rx_session_id = (src_addr & 0x0000000F00000000) >> 32; /* shift right 32 bits to get high 4 bits */

    tsc_write_reg_rx(mgmt->io_base, rx_dsptor_start_addr(id), reg_addr.u32);
    tsc_write_reg_rx(mgmt->io_base, tsc_rx_ctrl(id), reg_ctrl.u32);
}

hi_void _tee_tsc_hal_rx_set_buf_len(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id, hi_u32 src_len)
{
    rx_dsptor_length reg;

    reg.u32 = tsc_read_reg_rx(mgmt->io_base, rx_dsptor_length(id));
    reg.bits.rx_dsptor_length = src_len / TSR2RCIPHER_TS_PACKAGE_LEN; /* ts package number */
    reg.bits.rx_dsptor_cfg = 1;

    tsc_write_reg_rx(mgmt->io_base, rx_dsptor_length(id), reg.u32);
}

hi_void tee_tsc_hal_rx_set_buf(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id, hi_u64 src_buf_addr, hi_u32 src_buf_len)
{
    tsc_fatal_con_void_return(id >= mgmt->ch_cnt);
    id += TSR2RCIPHER_CH_BASE;

    /* rx buffer address */
    _tee_tsc_hal_rx_set_buf_addr(mgmt, id, src_buf_addr);

    /* rx buffer len */
    _tee_tsc_hal_rx_set_buf_len(mgmt, id, src_buf_len);
}

hi_void tee_tsc_hal_tx_config(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id, enum tsc_buf_type buf_type)
{
    tsc_tx_ctrl reg;

    tsc_fatal_con_void_return(id >= mgmt->ch_cnt);
    id += TSR2RCIPHER_CH_BASE;

    reg.u32 = tsc_read_reg_tx(mgmt->io_base, tsc_tx_ctrl(id));
    reg.bits.tx_buf_type  = buf_type;
    reg.bits.tx_press_dis = 1;  /* disable press */

    tsc_write_reg_tx(mgmt->io_base, tsc_tx_ctrl(id), reg.u32);

    tsc_com_equal(reg.u32, tsc_read_reg_tx(mgmt->io_base, tsc_tx_ctrl(id)));
}

hi_bool tee_tsc_hal_tx_get_dsptor_status(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id)
{
    tx_dsptor_ctrl reg;

    if (id >= mgmt->ch_cnt) {
        hi_log_err("id is invalid!\n");
        return HI_FALSE;
    }
    id += TSR2RCIPHER_CH_BASE;

    reg.u32 = tsc_read_reg_tx(mgmt->io_base, tx_dsptor_ctrl(id));

    return (reg.bits.tx_dsptor_full == 0x0);
}

hi_void _tee_tsc_hal_tx_set_buf_addr(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id, hi_u64 dst_addr)
{
    tx_dsptor_start_addr reg_addr;
    tsc_tx_ctrl          reg_ctrl;

    reg_addr.u32 = tsc_read_reg_tx(mgmt->io_base, tx_dsptor_start_addr(id));
    reg_ctrl.u32 = tsc_read_reg_tx(mgmt->io_base, tsc_tx_ctrl(id));

    reg_addr.bits.tx_dsptor_start_addr = dst_addr & 0x00000000FFFFFFFF;
    reg_ctrl.bits.tx_session_id = (dst_addr & 0x0000000F00000000) >> 32; /* shift right 32 bits to get high 4 bits */

    tsc_write_reg_tx(mgmt->io_base, tx_dsptor_start_addr(id), reg_addr.u32);
    tsc_write_reg_tx(mgmt->io_base, tsc_tx_ctrl(id), reg_ctrl.u32);
}

hi_void _tee_tsc_hal_tx_set_buf_len(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id, hi_u32 dst_len)
{
    tx_dsptor_length reg;

    reg.u32 = tsc_read_reg_tx(mgmt->io_base, tx_dsptor_length(id));
    reg.bits.tx_dsptor_length = dst_len / TSR2RCIPHER_TS_PACKAGE_LEN; /* ts package number */
    reg.bits.tx_dsptor_cfg = 1;

    tsc_write_reg_tx(mgmt->io_base, tx_dsptor_length(id), reg.u32);
}

hi_void tee_tsc_hal_tx_set_buf(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id, hi_u64 dst_buf_addr, hi_u32 dst_buf_len)
{
    tsc_fatal_con_void_return(id >= mgmt->ch_cnt);
    id += TSR2RCIPHER_CH_BASE;

    /* tx buffer address */
    _tee_tsc_hal_tx_set_buf_addr(mgmt, id, dst_buf_addr);

    /* tx buffer len */
    _tee_tsc_hal_tx_set_buf_len(mgmt, id, dst_buf_len);
}

hi_void tee_tsc_hal_set_sec_chan(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id, hi_bool rx_is_sec, hi_bool tx_is_sec)
{
    tsc_mode_ctrl reg;

    tsc_fatal_con_void_return(id >= mgmt->ch_cnt);
    id += TSR2RCIPHER_CH_BASE;

    reg.u32 = tsc_read_reg_rx(mgmt->io_base, tsc_mode_ctrl(id));
    if (rx_is_sec == HI_TRUE) {
        reg.bits.tsc_rx_sec_attr = 0;
    } else {
        reg.bits.tsc_rx_sec_attr = 1;
    }
    if (tx_is_sec == HI_TRUE) {
        reg.bits.tsc_tx_sec_attr = 0;
    } else {
        reg.bits.tsc_tx_sec_attr = 1;
    }

    tsc_write_reg_rx(mgmt->io_base, tsc_mode_ctrl(id), reg.u32);

    tsc_com_equal(reg.u32, tsc_read_reg_rx(mgmt->io_base, tsc_mode_ctrl(id)));
}

hi_void tee_tsc_hal_clr_chan(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id)
{
    hi_u32 i = 0;
    tsc_clear_req reg;

    tsc_fatal_con_void_return(id >= mgmt->ch_cnt);
    id += TSR2RCIPHER_CH_BASE;

    reg.u32 = tsc_read_reg_rx(mgmt->io_base, TSC_CLEAR_REQ);

    reg.bits.tsc_clear_chn_id = id;
    reg.bits.tsc_clear_chn_req = 1;

    tsc_write_reg_rx(mgmt->io_base, TSC_CLEAR_REQ, reg.u32);

    reg.u32 = tsc_read_reg_rx(mgmt->io_base, TSC_CLEAR_REQ);
    while (reg.bits.tsc_clear_chn_req != 0 && (i++ <= TSC_CHAN_CLEAR_TIMEOUT_CNT)) {
        hi_tee_drv_hal_msleep(1);
        reg.u32 = tsc_read_reg_rx(mgmt->io_base, TSC_CLEAR_REQ);
    }

    if (i >= TSC_CHAN_CLEAR_TIMEOUT_CNT) {
        hi_log_err("clear chan time out!\n");
    }
}

hi_void tee_tsc_hal_set_mode_ctl(tee_tsr2rcipher_mgmt *mgmt, tsr2rcipher_ch *rch,
    hi_u32 id, enum tsc_crypt_type crypt_type)
{
    tsc_mode_ctrl reg;

    tsc_fatal_con_void_return(id >= mgmt->ch_cnt);
    id += TSR2RCIPHER_CH_BASE;

    reg.u32 = tsc_read_reg_rx(mgmt->io_base, tsc_mode_ctrl(id));
    reg.bits.key_id     = (rch->ks_handle & 0x000000ff);
    reg.bits.dsc_type   = crypt_type;
    reg.bits.core_sel   = rch->core_type;
    reg.bits.pl_raw_sel = rch->mode;

    if (rch->is_odd_key == HI_TRUE) {
        reg.bits.odd_even_sel = 1;
    } else {
        reg.bits.odd_even_sel = 0;
    }

    if (rch->is_crc_check == HI_TRUE) {
        reg.bits.tsc_crc_en = 1;
    } else {
        reg.bits.tsc_crc_en = 0;
    }

    tsc_write_reg_rx(mgmt->io_base, tsc_mode_ctrl(id), reg.u32);

    tsc_com_equal(reg.u32, tsc_read_reg_rx(mgmt->io_base, tsc_mode_ctrl(id)));
}

hi_void tee_tsc_hal_en_mode_ctl(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id)
{
    tsc_mode_ctrl reg;

    tsc_fatal_con_void_return(id >= mgmt->ch_cnt);
    id += TSR2RCIPHER_CH_BASE;

    reg.u32 = tsc_read_reg_rx(mgmt->io_base, tsc_mode_ctrl(id));
    reg.bits.tsc_chn_en = 1;

    tsc_write_reg_rx(mgmt->io_base, tsc_mode_ctrl(id), reg.u32);

    tsc_com_equal(reg.u32, tsc_read_reg_rx(mgmt->io_base, tsc_mode_ctrl(id)));
}

hi_void tee_tsc_hal_dis_mode_ctl(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id)
{
    tsc_mode_ctrl reg;

    tsc_fatal_con_void_return(id >= mgmt->ch_cnt);
    id += TSR2RCIPHER_CH_BASE;

    reg.u32 = tsc_read_reg_rx(mgmt->io_base, tsc_mode_ctrl(id));
    reg.bits.tsc_chn_en = 0;

    tsc_write_reg_rx(mgmt->io_base, tsc_mode_ctrl(id), reg.u32);
}

hi_void tee_tsc_hal_lock_config(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id, hi_bool is_tee_lock)
{
    u_rx_sec_attr reg;

    tsc_fatal_con_void_return(id >= mgmt->ch_cnt);
    id += TSR2RCIPHER_CH_BASE;

    reg.u32 = tsc_read_reg_rx(mgmt->io_base, rx_sec_attr(id));
    if (is_tee_lock == HI_TRUE) {
        reg.bits.tsc_chn_tee_lock = 1;
    } else {
        reg.bits.tsc_chn_ree_lock = 1;
    }

    tsc_write_reg_rx(mgmt->io_base, rx_sec_attr(id), reg.u32);
}

hi_void tee_tsc_hal_lock_deconfig(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id)
{
    u_rx_sec_attr reg;

    tsc_fatal_con_void_return(id >= mgmt->ch_cnt);
    id += TSR2RCIPHER_CH_BASE;

    reg.u32 = tsc_read_reg_rx(mgmt->io_base, rx_sec_attr(id));
    reg.bits.tsc_chn_tee_lock = 0;
    reg.bits.tsc_chn_ree_lock = 0;

    tsc_write_reg_rx(mgmt->io_base, rx_sec_attr(id), reg.u32);
}

hi_u32 tee_tsc_hal_top_get_tx_raw_int_status(tee_tsr2rcipher_mgmt *mgmt)
{
    tsc_iraw reg;

    reg.u32 = tsc_read_reg_top(mgmt->io_base, TSC_IRAW);

    return reg.bits.tx2cpu_iraw;
}

hi_void tee_tsc_hal_top_cls_tx_int_status(tee_tsr2rcipher_mgmt *mgmt)
{
    tsc_iraw reg;

    reg.u32 = 0;
    reg.bits.tx2cpu_iraw = 1;

    tsc_write_reg_top(mgmt->io_base, TSC_IRAW, reg.u32);
}

hi_u32 tee_tsc_hal_tx_get_dsc_rd_total_int_status(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id)
{
    iraw_tx reg;

    tsc_condition_return_value(id >= mgmt->ch_cnt, HI_FAILURE);
    id += TSR2RCIPHER_CH_BASE;

    reg.u32 = tsc_read_reg_tx(mgmt->io_base, iraw_tx(id));

    return reg.bits.iraw_tx_dsptor_done;
}

hi_void tee_tsc_hal_tx_cls_dsc_rd_total_int_status(tee_tsr2rcipher_mgmt *mgmt, hi_u32 id)
{
    iraw_tx reg;

    tsc_fatal_con_void_return(id >= mgmt->ch_cnt);
    id += TSR2RCIPHER_CH_BASE;

    reg.u32 = 0;
    reg.bits.iraw_tx_dsptor_done = 1;

    tsc_write_reg_tx(mgmt->io_base, iraw_tx(id), reg.u32);
}

