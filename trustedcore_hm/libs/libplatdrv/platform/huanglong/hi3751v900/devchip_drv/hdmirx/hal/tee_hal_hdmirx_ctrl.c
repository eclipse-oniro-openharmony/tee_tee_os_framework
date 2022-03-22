/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Implementation of ctrl functions
 * Author: Hisilicon multimedia interface software group
 * Create: 2020-03-09
 */
#include "tee_hal_hdmirx_comm.h"
#include "tee_hal_hdmirx_reg.h"

hi_u32 tee_hal_hdmirx_ctrl_get_licence(hi_void)
{
    return hdmirx_hal_sys_ctrl_read_fld_align(REG_SYS_LICENSE_SUPPORT, HDMIRX_LICENSE_SUPPORT);
}

hi_void tee_hal_hdmirx_ctrl_crg_init(hi_void)
{
    /* cken */
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_APB_CKEN, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_MEDIA_CFG_CKEN, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_MEDIA_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_LINK_CFG_CKEN, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_LINK_CKEN, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_TEST_PHYREF_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_AON_CKEN, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_VI_INTF_CKEN, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_DSCD_CKEN, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_LINK_CKEN, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_MEDIA_CKEN, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_TEST_PHYREF_CLK_DIV, 0x2); /* refclk / 3 */

    /* cken */
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_APB_CKEN, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_MEDIA_CFG_CKEN, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_MEDIA_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_LINK_CFG_CKEN, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_LINK_CKEN, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_TEST_PHYREF_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_TEST_PHYREF_CLK_DIV, 0x2); /* refclk / 3 */

    /* de-reset */
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_APB_SRST_REQ, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_SRST_REQ, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_AON_APB_SRST_REQ, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_AON_SRST_REQ, HI_FALSE);

    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_APB_SRST_REQ, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_SRST_REQ, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_DSCD_SRST_REQ, HI_FALSE);
}

hi_void tee_hal_hdmirx_ctrl_crg_deinit(hi_void)
{
    /* cken */
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_APB_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_MEDIA_CFG_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_MEDIA_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_LINK_CFG_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_LINK_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_TEST_PHYREF_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_AON_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_VI_INTF_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_DSCD_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_LINK_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_MEDIA_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_TEST_PHYREF_CLK_DIV, 0x2); /* refclk / 3 */

    /* cken */
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_APB_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_MEDIA_CFG_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_MEDIA_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_LINK_CFG_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_LINK_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_TEST_PHYREF_CKEN, HI_FALSE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_TEST_PHYREF_CLK_DIV, 0x2); /* refclk / 3 */

    /* de-reset */
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_APB_SRST_REQ, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_PWD_SRST_REQ, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_AON_APB_SRST_REQ, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_287, HDMIRX_2P0_AON_SRST_REQ, HI_TRUE);

    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_APB_SRST_REQ, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_2P1_PWD_SRST_REQ, HI_TRUE);
    hdmirx_hal_crg_write_fld_align(REG_PERI_CRG_288, HDMIRX_DSCD_SRST_REQ, HI_TRUE);
}

