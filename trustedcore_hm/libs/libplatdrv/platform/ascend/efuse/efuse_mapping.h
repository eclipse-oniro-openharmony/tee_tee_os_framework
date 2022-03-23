/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
* Description: eFuse mapping file
* Author: huawei
* Create: 2020/4/18
*/
#ifndef _EFUSE_MAPPING_H_
#define _EFUSE_MAPPING_H_

typedef struct efuse_desc {
    unsigned int start;
    unsigned int size;
    unsigned int word;
    unsigned int mask;
} efuse_desc_t;

const efuse_desc_t g_efuse0[] = {
    {
    .start = 800,
    .size = 4,
    .word = 25,
    .mask = 0x7800000,
    }, /* sys_access_lock */
    {
    .start = 1280,
    .size = 8,
    .word = 40,
    .mask = 0x3FC00,
    }, /* avs_margin_test */
    {
    .start = 1568,
    .size = 22,
    .word = 49,
    .mask = 0xFFFFFC00,
    }, /* ns_forbid_p1(8)/ allscan_forbid(1)/ j2djs_forbid(1)/ j2dj_id_forbid(1)/ key_cfged(4)/
       jtag_forbid(3)/ reserved(4) */
    {
    .start = 1664,
    .size = 384,
    .word = 52,
    .mask = 0xffffffff,
    }, /* rompatch */
    {
    .start = 3456,
    .size = 256,
    .word = 108,
    .mask = 0xffffffff,
    }, /* rotauk */
    {
    .start = 3712,
    .size = 288,
    .word = 116,
    .mask = 0xffffffff,
    }, /* imrk1(write only) */
    {
    .start = 4000,
    .size = 64,
    .word = 125,
    .mask = 0xffffffff,
    }, /* dbgen(1)/ niden(1)/ sdbg_ctrl(2)/ dis_sm3_sm4(4)/ dis_des_tdes(2)/ dis_md5_sh1(2)
       imgenc_cfg1(2)/ km_wk_visable(2)/ ns_forbid_p2(16)/ hiss_djtag_bypass(2)/ boot_gm_en(4)/
       dis_crypto_debug(2)/ efuse_djtag_ctrl(2)/ dis_trng_ctrl_sel_hiss(2)/ dis_trng_tp_hiss(2)/ imgenc_cfg2_1(1)
       sj2tdre_forbid(1)/ dice_enable(2)/ ns_forbid_p3(8)/ boot_spiflash_mode(1)/ dcls_control(4)/ reserved(1) */
    {
    .start = 4064,
    .size = 20,
    .word = 127,
    .mask = 0xFFFFF000,
    }, /* reserved(20) */
};

const efuse_desc_t g_efuse1[] = {
    {
    .start = 0,
    .size = 288,
    .word = 0,
    .mask = 0xffffffff,
    }, /* osnvcnt(224)/ rvksubkeyidmask1(32)/ rvksubkeyidmask2(32) */
    {
    .start = 288,
    .size = 32,
    .word = 9,
    .mask = 0xffffffff,
    }, /* xloadernv/l2nvcnt(32) */
    {
    .start = 320,
    .size = 256,
    .word = 10,
    .mask = 0xffffffff,
    }, /* rotpk1 */
    {
    .start = 576,
    .size = 320,
    .word = 18,
    .mask = 0xffffffff,
    }, /* subkeycat1(32)/ rotpk2(256)/ subkeycat2(32) */
    {
    .start = 896,
    .size = 128,
    .word = 28,
    .mask = 0xffffffff,
    }, /* customer_locked~reverved(12) */
    {
    .start = 1024,
    .size = 288,
    .word = 32,
    .mask = 0xffffffff,
    }, /* write only(288) */
    {
    .start = 1312,
    .size = 64,
    .word = 41,
    .mask = 0xffffffff,
    }, /* huk_cfged(1) ~ reverved(31) */
    {
    .start = 1376,
    .size = 576,
    .word = 43,
    .mask = 0xffffffff,
    }, /* uds(288) / ipk1(288) */
    {
    .start = 1952,
    .size = 576,
    .word = 61,
    .mask = 0xffffffff,
    }, /* imrk2(288) / ipk2(288) */
    {
    .start = 2528,
    .size = 544,
    .word = 79,
    .mask = 0xffffffff,
    }, /* imrk2(288) / ipk2(288) */
    {
    .start = 3072,
    .size = 576,
    .word = 96,
    .mask = 0xffffffff,
    }, /* rsv1(288)/rsv2(288) */
    {
    .start = 3648,
    .size = 320,
    .word = 114,
    .mask = 0xffffffff,
    }, /* ssk(256)/ jtag_forbid_bypass(2)/ extendBit(30)/ jtagauth_keyid(32) */
    {
    .start = 3968,
    .size = 128,
    .word = 124,
    .mask = 0xffffffff,
    }, /* reserved(128) */
};
#endif
