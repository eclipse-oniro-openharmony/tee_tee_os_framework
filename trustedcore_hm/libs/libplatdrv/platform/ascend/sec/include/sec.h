/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
* Description: the head of sec internal function
* Author: chenyao
* Create: 2019/12/30
*/
#ifndef __SEC_H__
#define __SEC_H__

#include <stdint.h>

#define SEC_BASE_ADDR                                               0x8A800000U
#define MST_OOO_REG_ADDR                                            (SEC_BASE_ADDR + 0x00300000)
#define SEC_PF_REG_ADDR                                             (SEC_BASE_ADDR + 0x301000)
#define SEC_POE_REG_ADDR                                            (SEC_BASE_ADDR + 0x302000)
#define SEC_BDFIFO_REG_ADDR                                         (SEC_BASE_ADDR + 0x00310000)
#define SEC_PF_BAR_BASE_ADDR                                        (SEC_BASE_ADDR + 0x0)
#define SEC_VF_BAR_BASE_ADDR                                        (SEC_BASE_ADDR + 0x3FFFFF)

#define SEC_BDF_EN_REG                                              (SEC_BDFIFO_REG_ADDR + 0x0000)
#define BDF_EN_STATUS_REG                                           (SEC_BDFIFO_REG_ADDR + 0x0004)
#define SEC_BDF_CFG_AWUSER_REG                                      (SEC_BDFIFO_REG_ADDR + 0x000C)
#define SEC_BDF_CFG_ARUSER_REG                                      (SEC_BDFIFO_REG_ADDR + 0x0010)
#define SEC_BDF_CFG_PD_TAG_REG                                      (SEC_BDFIFO_REG_ADDR + 0x001C)
#define SEC_BDF_CNT_CLR_CE_REG                                      (SEC_BDFIFO_REG_ADDR + 0x0020)
#define SEC_BDF_CFG_SKIP_LENGTH_REG                                 (SEC_BDFIFO_REG_ADDR + 0x0028)
#define ACC_STREAMID_S_REG                                          (SEC_BDFIFO_REG_ADDR + 0x002C)
#define KM_REQ_START_REG                                            (SEC_BDFIFO_REG_ADDR + 0x0038)
#define KM_REQ_DONE_REG                                             (SEC_BDFIFO_REG_ADDR + 0x003C)
#define KM_AUTO_REQ_START_REG                                       (SEC_BDFIFO_REG_ADDR + 0x0040)
#define KM_AUTO_REQ_DONE_REG                                        (SEC_BDFIFO_REG_ADDR + 0x0044)
#define BDF_ECO_RW_REG                                              (SEC_BDFIFO_REG_ADDR + 0x0080)

#define SEC_BDF_DATA_LOW_REG                                        (SEC_BDFIFO_REG_ADDR + 0x0100)
#define SEC_BDF_DATA_HIG_REG                                        (SEC_BDFIFO_REG_ADDR + 0x0104)
#define SEC_BDF_PKG_DOING_CNT_REG                                   (SEC_BDFIFO_REG_ADDR + 0x0108)
#define SEC_BDF_PKG_GET_CNT_REG                                     (SEC_BDFIFO_REG_ADDR + 0x010C)
#define SEC_BDF_PKG_DONE_CNT_REG                                    (SEC_BDFIFO_REG_ADDR + 0x0110)
#define SEC_BDF_STATUS_REG                                          (SEC_BDFIFO_REG_ADDR + 0x0114)
#define SEC_BDF_SW_POP_EN_REG                                       (SEC_BDFIFO_REG_ADDR + 0x0118)
#define SEC_BDF_SW_POP_DAT_LOW_REG                                  (SEC_BDFIFO_REG_ADDR + 0x0120)
#define SEC_BDF_SW_POP_DAT_HIG_REG                                  (SEC_BDFIFO_REG_ADDR + 0x0124)
#define SEC_BDF_FIFO_STATUS_REG                                     (SEC_BDFIFO_REG_ADDR + 0x0128)

#define SEC_BDF_INT_ENABLE_REG                                      (SEC_BDFIFO_REG_ADDR + 0x0200)
#define SEC_BDF_RINT_SOURCE_REG                                     (SEC_BDFIFO_REG_ADDR + 0x0204)

#define SEC_BDF_DROP_CNT_REG                                        (SEC_BDFIFO_REG_ADDR + 0x0304)
#define SEC_BDF_SPOP_CNT_REG                                        (SEC_BDFIFO_REG_ADDR + 0x031C)
#define SEC_KM_KEY_INFO_CMD_REG                                     (SEC_BDFIFO_REG_ADDR + 0x0324)
#define SEC_KM_KEY_INFO_REG                                         (SEC_BDFIFO_REG_ADDR + 0x0328)

#define SEC_PF_ABNORMAL_INT_SOURCE_REG                              (SEC_PF_REG_ADDR + 0x0010)

#define SEC_MEM_START_INIT_REG                                      (SEC_PF_REG_ADDR + 0x0100)
#define SEC_MEM_INIT_DONE_REG                                       (SEC_PF_REG_ADDR + 0x0104)
#define SEC_CNT_CLR_CE_REG                                          (SEC_PF_REG_ADDR + 0x0120)
#define SEC_FSM_MAX_CNT_REG                                         (SEC_PF_REG_ADDR + 0x0124)
#define SEC_SGL_OFFSET_CONTROL_REG                                  (SEC_PF_REG_ADDR + 0x0130)
#define SEC_PAGE_SIZE_CONTROL_REG                                   (SEC_PF_REG_ADDR + 0x0134)
#define SEC_DIF_CRC_INIT_REG                                        (SEC_PF_REG_ADDR + 0x0138)

#define SEC_CONTROL_REG                                             (SEC_PF_REG_ADDR + 0x0200)
#define SEC_AXI_CACHE_CFG_REG                                       (SEC_PF_REG_ADDR + 0x0210)
#define SEC_SNPATTR_CFG_REG                                         (SEC_PF_REG_ADDR + 0x0218)
#define SEC_INTERFACE_USER_CTRL0_REG                                (SEC_PF_REG_ADDR + 0x0220)
#define SEC_INTERFACE_USER_CTRL1_REG                                (SEC_PF_REG_ADDR + 0x0224)
#define SEC_BD_PACKET_OST_CFG_REG                                   (SEC_PF_REG_ADDR + 0x0240)
#define SEC_SAA_EN_REG                                              (SEC_PF_REG_ADDR + 0x0270)


#define SEC_CHAIN_ABN_RD_ADDR_LOW_REG                               (SEC_PF_REG_ADDR + 0x0300)
#define SEC_CHAIN_ABN_RD_ADDR_HIG_REG                               (SEC_PF_REG_ADDR + 0x0304)
#define SEC_CHAIN_ABN_RD_LEN_REG                                    (SEC_PF_REG_ADDR + 0x0308)
#define SEC_CHAIN_ABN_WR_ADDR_LOW_REG                               (SEC_PF_REG_ADDR + 0x0310)
#define SEC_CHAIN_ABN_WR_ADDR_HIG_REG                               (SEC_PF_REG_ADDR + 0x0314)
#define SEC_CHAIN_ABN_WR_LEN_REG                                    (SEC_PF_REG_ADDR + 0x0318)
#define SEC_ECO_RW_REG                                              (SEC_PF_REG_ADDR + 0x0580) /* 0x0580+sec_eco_reg_num*0x04 */

#define SEC_ECC_1BIT_CNT_REG                                        (SEC_PF_REG_ADDR + 0x0C00)
#define SEC_ECC_2BIT_CNT_REG                                        (SEC_PF_REG_ADDR + 0x0C10)
#define SEC_SAA_ACC_REG                                             (SEC_PF_REG_ADDR + 0x0C3C) /* 0x0C20+sec_all_channel_num*0x04 */
#define SEC_BD_MEM_RD_CFG_REG                                       (SEC_PF_REG_ADDR + 0x0C84)


#define AM_CTRL_GLOBAL_REG                                          (MST_OOO_REG_ADDR + 0x0000)
#define AM_CFG_MAX_TRANS_REG                                        (MST_OOO_REG_ADDR + 0x0010)
#define AM_CURR_TRANS_RETURN_REG                                    (MST_OOO_REG_ADDR + 0x0150)

#define SEC_LINK_RSV_REG                                            (SEC_POE_REG_ADDR + 0x0910)

/* QM */
#define QM_PF_REG_BASE_ADDR                                         0x0100000
#define QM_MEM_START_INIT_REG                                       (QM_PF_REG_BASE_ADDR + 0x0040)
#define QM_MEM_INIT_DONE_REG                                        (QM_PF_REG_BASE_ADDR + 0x0044)
#define QM_CACHE_CTL_REG                                            (QM_PF_REG_BASE_ADDR + 0x0050)
#define QM_VFT_CFG_OP_ENABLE_REG                                    (QM_PF_REG_BASE_ADDR + 0x0054)
#define QM_VFT_CFG_OP_WR_REG                                        (QM_PF_REG_BASE_ADDR + 0x0058)
#define QM_VFT_CFG_TYPE_REG                                         (QM_PF_REG_BASE_ADDR + 0x005C)
#define QM_VFT_CFG_ADDRESS_REG                                      (QM_PF_REG_BASE_ADDR + 0x0060)
#define QM_VFT_CFG_DATA_L_REG                                       (QM_PF_REG_BASE_ADDR + 0x0064)
#define QM_VFT_CFG_DATA_H_REG                                       (QM_PF_REG_BASE_ADDR + 0x0068)
#define QM_VFT_CFG_RDY_REG                                          (QM_PF_REG_BASE_ADDR + 0x006C)

#define QM_ARUSER_M_CFG_0_REG                                       (QM_PF_REG_BASE_ADDR + 0x0084)
#define QM_ARUSER_M_CFG_1_REG                                       (QM_PF_REG_BASE_ADDR + 0x0088)
#define QM_ARUSER_M_CFG_2_REG                                       (QM_PF_REG_BASE_ADDR + 0x008C)
#define QM_ARUSER_M_CFG_ENABLE_REG                                  (QM_PF_REG_BASE_ADDR + 0x0090)
#define QM_AWUSER_M_CFG_0_REG                                       (QM_PF_REG_BASE_ADDR + 0x0094)
#define QM_AWUSER_M_CFG_1_REG                                       (QM_PF_REG_BASE_ADDR + 0x0098)
#define QM_AWUSER_M_CFG_2_REG                                       (QM_PF_REG_BASE_ADDR + 0x009C)
#define QM_AWUSER_M_CFG_ENABLE_REG                                  (QM_PF_REG_BASE_ADDR + 0x00A0)
#define QM_WUSER_M_CFG_REG                                          (QM_PF_REG_BASE_ADDR + 0x00A4)
#define QM_WUSER_M_CFG_ENABLE_REG                                   (QM_PF_REG_BASE_ADDR + 0x00A8)
#define QM_AXI_M_CFG_REG                                            (QM_PF_REG_BASE_ADDR + 0x00AC)
#define QM_AXI_M_CFG_ENABLE_REG                                     (QM_PF_REG_BASE_ADDR + 0x00B0)
#define QM_SRIOCAP_VF_STRIDE_REG                                    (QM_PF_REG_BASE_ADDR + 0x00B4)

#define QM_PEH_AXUSER_CFG_REG                                       (QM_PF_REG_BASE_ADDR + 0x00CC)
#define QM_PEH_AXUSER_CFG_ENABLE_REG                                (QM_PF_REG_BASE_ADDR + 0x00D0)

#define QM_PEH_VENDOR_ID_REG                                        (QM_PF_REG_BASE_ADDR + 0x00DC)
#define QM_PEH_DFX_INFO0_REG                                        (QM_PF_REG_BASE_ADDR + 0x00FC)

/* PEH */
#define PEH_PF_REGS_BASE_ADDR                                       0xD7700000U
#define PCIHDR_ID_REG                                               (PEH_PF_REGS_BASE_ADDR + 0x0000)
#define PCIHDR_CMDSTS_REG                                           (PEH_PF_REGS_BASE_ADDR + 0x0004)
#define PCIHDR_BAR2_REG                                             (PEH_PF_REGS_BASE_ADDR + 0x0018)
#define SRIOV_CAP_HEADER_REG                                        (PEH_PF_REGS_BASE_ADDR + 0x0020)

#define PCIHDR_BAR3_REG                                             (PEH_PF_REGS_BASE_ADDR + 0x001C)
#define MSI_ADD_REG                                                 (PEH_PF_REGS_BASE_ADDR + 0x0084)
#define MSI_UP_ADD_REG                                              (PEH_PF_REGS_BASE_ADDR + 0x0088)
#define MSI_DATA_REG                                                (PEH_PF_REGS_BASE_ADDR + 0x008C)
#define MSI_MASK_REG                                                (PEH_PF_REGS_BASE_ADDR + 0x0094)
#define MSIX_CAP_HEADER_REG                                         (PEH_PF_REGS_BASE_ADDR + 0x00A0)

#define SRIOV_CTRL_REG                                              (PEH_PF_REGS_BASE_ADDR + 0x0208)
#define INIT_VF_NUMBER_REG                                          (PEH_PF_REGS_BASE_ADDR + 0x020C)
#define FUNC_DEP_VF_NUM_REG                                         (PEH_PF_REGS_BASE_ADDR + 0x0210)
#define VF_RID_SETTING_REG                                          (PEH_PF_REGS_BASE_ADDR + 0x0214)
#define VF_DEVICE_ID_REG                                            (PEH_PF_REGS_BASE_ADDR + 0x0218)
#define VF_BAR2_REG                                                 (PEH_PF_REGS_BASE_ADDR + 0x022C)
#define VF_BAR3_REG                                                 (PEH_PF_REGS_BASE_ADDR + 0x0230)

/* PBU */
#define SC_SEC_PBU_REGS_BASE_ADDR                                   0xD7410000U
#define SC_SEC_PBU_PCIHDR_CMDSTS_REG                                (SC_SEC_PBU_REGS_BASE_ADDR + 0x0004)
#define SC_SEC_PBU_PCIHDR_BUS_NUM_REG                               (SC_SEC_PBU_REGS_BASE_ADDR + 0x0018)
#define SC_SEC_PBU_PCIHDR_PRE_MEM_BASE_LIMIT_REG                    (SC_SEC_PBU_REGS_BASE_ADDR + 0x0024)
#define SC_SEC_PBU_PCIHDR_PRE_MEM_BASE_32_UPADR_REG                 (SC_SEC_PBU_REGS_BASE_ADDR + 0x0028)
#define SC_SEC_PBU_PCIHDR_PRE_MEM_LIMIT_32_UPADR_REG                (SC_SEC_PBU_REGS_BASE_ADDR + 0x002C)

#define PCIHDR_BAR3_REG                                             (PEH_PF_REGS_BASE_ADDR + 0x001C)
#define MSI_ADD_REG                                                 (PEH_PF_REGS_BASE_ADDR + 0x0084)
#define MSI_UP_ADD_REG                                              (PEH_PF_REGS_BASE_ADDR + 0x0088)
#define MSI_DATA_REG                                                (PEH_PF_REGS_BASE_ADDR + 0x008C)
#define MSI_MASK_REG                                                (PEH_PF_REGS_BASE_ADDR + 0x0094)
#define MSIX_CAP_HEADER_REG                                         (PEH_PF_REGS_BASE_ADDR + 0x00A0)

#define SRIOV_CTRL_REG                                              (PEH_PF_REGS_BASE_ADDR + 0x0208)
#define INIT_VF_NUMBER_REG                                          (PEH_PF_REGS_BASE_ADDR + 0x020C)
#define VF_RID_SETTING_REG                                          (PEH_PF_REGS_BASE_ADDR + 0x0214)

/* DISP */
#define CFG_DISP_BASE_ADDR                                          0x88060000U
#define DISP_ECAM_DAW_EN_REG                                        (CFG_DISP_BASE_ADDR + 0x00DC)


/* HAC SUBCTRL */
#define HAC_SUBCTRL_REG_ADDR                                        0x880C0000U
#define SC_SEC_ICG_DIS_REG                                          (HAC_SUBCTRL_REG_ADDR + 0x66C)
#define SC_SEC_ICG_EN_REG                                           (HAC_SUBCTRL_REG_ADDR + 0x668)
#define SC_SEC_RESET_REQ_REG                                        (HAC_SUBCTRL_REG_ADDR + 0xA88)
#define SC_SEC_RESET_DREQ_REG                                       (HAC_SUBCTRL_REG_ADDR + 0xA94)
#define SC_SEC_ICG_ST_REG                                           (HAC_SUBCTRL_REG_ADDR + 0x5668)
#define SC_SEC_RESET_ST_REG                                         (HAC_SUBCTRL_REG_ADDR + 0x5A88)

/* Test addr */
#define DEFAULT_VALUE                   0x0

#define SEC_RST                         0xF
#define SEC_RST_REF                     0xF
#define SEC_RST_REL                     0xF
#define SEC_RST_REL_REF                 0x0
#define SEC_CLOCK_OPEN                  0xF
#define SEC_CLOCK_OPEN_REF              0xF
#define SEC_CLOCK_CLOSE                 0xF
#define SEC_CLOCK_CLOSE_REF             0x0

#define MSI_MASK_CLOSE                  0x0

#define SEC_BD_FIFO_EN                  0x1
#define SEC_BDF_CNT_CLR_DISABLE         0x0
#define SEC_MAX_SKIP_LENGTH             0x7
#define SEC_POP_PUSH_EN                 0x3
#define SEC_BDF_INT_DISABLE             0x0
#define SEC_READ_BD_OUTSTANDING         0x18
#define SEC_MEM_INIT_EN                 0x1
#define SEC_MEM_INIT_DONE               0x1
#define SEC_SAA_EN                      0x7
#define LISTADD_LIMIT                   0x4

#define SEC_S_TYPE                      0x1
#define SEC_N_TYPE                      0x2
#define SEC_DEC                         0x2
#define SEC_ENC                         0x1
#define SEC_MAC_TO_DDR                  0x1
#define SEC_DST_ADDR_EN                 0x1
#define SEC_EDEC_AUTH                   0x0
#define SEC_DST_ADDR_DISABLE            0x0
#define SEC_NO_SCENE                    0x0
#define SEC_PBUFFER                     0x0
#define SEC_READ_FROM_DDR               0x0
#define SEC_LAST_BLOCK_PADDING          0x0
#define SEC_LAST_BLOCK_NO_PADDING       0x1
#define SEC_GCM_MAC_LEN                 0x10
#define SEC_CCM_MAC_LEN                 0x08
#define SEC_AUTH_IV_OFF                 0x0
#define SEC_AUTH_IV_ON                  0x1
#define SEC_STEAM                       0x7
#define SEC_GCM_UPDATE_IV               0x4
#define SEC_GCM_AKEY_M                  0x2
#define SEC_GCM_AKEY_Q                  0x4

#define SEC_PBKDF2                      0x8

#define SEC_AES256_LEN                  0x2
#define SEC_OFB                         0x3
#define SEC_CTR                         0x4
#define SEC_CCM                         0x5
#define SEC_GCM                         0x6
#define SEC_GMAC                        0x22
#define SEC_CMAC                        0x21

#define SEC_UDS_KEY                     0x8
#define SEC_HMAC_SHA256_MAC_LEN         0x8
#define SEC_HMAC_SHA256_AKEY_LEN        0x8
#define SEC_HMAC_SHA256                 0x11

#define SEC_BDFIFO_FULL                 0x1
#define SEC_DELAY_TIME                  0xFFFF
#define SEC_ECO_RW_CONFIG               0x700
#define SEC_SHIFT32                     0x20

#define AXI_MASTER_OOO_OUTSTANDING      0x00001010
#define AM_CURR_TRANS_FINISH            0x3

#define TIMEOUT                         0xFFFFF
/* 2.5s refer to SEC FS  */
#define BD_CNT_TIMEOUT                  2500000
#define INIT_DONE                       0x5A5A5A5A
#define TIMEOUT0                        0xffff

#define SEC_ECAM_DAW_ON                 0xFF
#define SEC_PCIHDR_START                0x106
#define SEC_PCIHDR_RD_START             0x100106
#define SEC_PF_BAR_ADDR_L               0x8A800000U
#define SEC_PF_BAR_ADDR_RD_L            0x8A80000CU

#define SEC_PF_BAR_ADDR_H               0x0
#define SEC_SRIOV_ON                    0xFF
#define SEC_SRIOV_RD_ON                 0x19
#define SEC_VF_NUMBER                   0x1
#define SEC_VF_BAR_ADDR_L               0x8AC00000U
#define SEC_VF_BAR_ADDR_RD_L            0x8AC0000CU
#define SEC_VF_BAR_ADDR_H               0x0
#define SEC_PBU_CMDSTS_CFG              0x106
#define SEC_PBU_CMDSTS_RD_CFG           0x100106
#define SEC_PBU_MEM_CFG                 0x8B008A80U
#define SEC_PBU_MEM_RD_CFG              0x8B018A81U
#define SEC_CLK_TIME_DELAY              0x1
#define BD_CNT_DELAY_1US                0x1

typedef union {
    struct {
        uint32_t bd_type                    : 4;
        uint32_t cipher                     : 2;
        uint32_t auth                       : 2;
        uint32_t seq                        : 1;
        uint32_t de                         : 2;
        uint32_t scene                      : 4;
        uint32_t src_addr_type              : 3;
        uint32_t dst_addr_type              : 3;
        uint32_t stream_protocol            : 3;
        uint32_t reserved0                  : 8;
    } bits;
    uint32_t word0;
} U_SEC_BD_WORD0;

typedef union {
    struct {
        uint32_t nonce_len                  : 4;
        uint32_t huk                        : 1;
        uint32_t key_s                      : 1;
        uint32_t ci_gen                     : 2;
        uint32_t ai_gen                     : 2;
        uint32_t auth_pad                   : 2;
        uint32_t c_s                        : 2;
        uint32_t reserved1                  : 2;
        uint32_t rhf                        : 1;
        uint32_t cipher_key_type            : 2;
        uint32_t auth_key_type              : 2;
        uint32_t write_frame_len            : 3;
        uint32_t cal_iv_addr_en             : 1;
        uint32_t tls_len_update             : 1;
        uint32_t reserved2                  : 5;
        uint32_t bd_ivld                    : 1;
    } bits;
    uint32_t word1;
} U_SEC_BD_WORD1;

typedef union {
    struct {
        uint32_t mac_len                    : 5;
        uint32_t akey_len                   : 6;
        uint32_t a_alg                      : 6;
        uint32_t key_sel                    : 4;
        uint32_t update_key                 : 1;
        uint32_t reserved3                  : 10;
    } bits;
    uint32_t word2;
} U_SEC_BD_WORD2;

typedef union {
    struct {
        uint32_t c_icv_len                  : 6;
        uint32_t c_width                    : 3;
        uint32_t ckey_len                   : 3;
        uint32_t c_mode                     : 4;
        uint32_t c_alg                      : 4;
        uint32_t reserved4                  : 12;
    } bits;
    uint32_t word3;
} U_SEC_BD_WORD3;

typedef union {
    struct {
        uint32_t auth_len                   : 24;
        uint32_t iv_offset_l                : 8;
    } bits;
    uint32_t word4;
} U_SEC_BD_WORD4;

typedef union {
    struct {
        uint32_t cipher_len                 : 24;
        uint32_t iv_offset_h                : 8;
    } bits;
    uint32_t word5;
} U_SEC_BD_WORD5;

typedef union {
    struct {
        uint32_t auth_src_offset            : 16;
        uint32_t cipher_src_offset          : 16;
    } bits;
    uint32_t word6;
} U_SEC_BD_WORD6;

typedef union {
    struct {
        uint32_t cs_ip_header_offset        : 16;
        uint32_t cs_udp_header_offset       : 16;
    } bits;
    uint32_t word7;
} U_SEC_BD_WORD7;

typedef union {
    struct {
        uint32_t deal_esp_ah                : 4;
        uint32_t protocol_type              : 4;
        uint32_t mode                       : 2;
        uint32_t ip_type                    : 2;
        uint32_t reserved5                  : 4;
        uint32_t next_header                : 8;
        uint32_t padding_length             : 8;
    } data1;
    struct {
        uint32_t pass_word_len              : 16;
        uint32_t dk_len                     : 16;
    } data2;
    uint32_t word8;
} U_SEC_BD_WORD8;

typedef union {
    struct {
        uint32_t salt_vh                    : 8;
        uint32_t salt_h                     : 8;
        uint32_t salt_l                     : 8;
        uint32_t salt_vl                    : 8;
    } bits;
    uint32_t word9;
} U_SEC_BD_WORD9;

typedef union {
    struct {
        uint32_t tag                        : 16;
        uint32_t reserved6                  : 16;
    } bits;
    uint32_t word10;
} U_SEC_BD_WORD10;

typedef union {
    struct {
        uint32_t cipher_pad_type            : 4;
        uint32_t cipher_pad_len             : 8;
        uint32_t cipher_pad_data_type       : 4;
        uint32_t cipher_pad_len_field       : 2;
        uint32_t reserved7                  : 14;
    } data1;
    struct {
        uint32_t deal_tls_1p3               : 3;
        uint32_t reserved8                  : 5;
        uint32_t plaintext_type             : 8;
        uint32_t padding_length_1p3         : 16;
    } data2;
    uint32_t word11;
} U_SEC_BD_WORD11;

typedef union {
    uint32_t long_auth_data_len_l;
    uint32_t sn_l;
} U_SEC_BD_WORD12;

typedef union {
    uint32_t long_auth_data_len_h;
    uint32_t sn_h;
    struct {
        uint32_t tls_1p3_type_back          : 8;
        uint32_t reserved9                  : 8;
        uint32_t padding_length_1p3_back    : 16;
    } write_back;
    uint32_t word13;
} U_SEC_BD_WORD13;

typedef union {
    struct {
        volatile uint32_t done              : 1;
        uint32_t icv                        : 3;
        uint32_t csc                        : 3;
        uint32_t flag                       : 3;
        uint32_t reserved10                 : 6;
        uint32_t error_type                 : 8;
        uint32_t warning_type               : 8;
    } bits;
    uint32_t word28;
} U_SEC_BD_WORD28;

typedef union {
    struct {
        uint32_t mac_i_vh                   : 8;
        uint32_t mac_i_h                    : 8;
        uint32_t mac_i_l                    : 8;
        uint32_t mac_i_vl                   : 8;
    } bits;
    uint32_t word29;
} U_SEC_BD_WORD29;

typedef union {
    struct {
        uint32_t checksum_i                 : 16;
        uint32_t reserved11                 : 16;
    } bits;
    uint32_t word30;
} U_SEC_BD_WORD30;


typedef struct {
    /* word0 */
    U_SEC_BD_WORD0  sec_bd_word0;

    /* word1 */
    U_SEC_BD_WORD1  sec_bd_word1;

    /* word2 */
    U_SEC_BD_WORD2  sec_bd_word2;

    /* word3 */
    U_SEC_BD_WORD3  sec_bd_word3;

    /* word4 */
    U_SEC_BD_WORD4  sec_bd_word4;

    /* word5 */
    U_SEC_BD_WORD5  sec_bd_word5;

    /* word6 */
    U_SEC_BD_WORD6  sec_bd_word6;

    /* word7 */
    U_SEC_BD_WORD7  sec_bd_word7;

    /* word8 */
    U_SEC_BD_WORD8  sec_bd_word8;

    /* word9 */
    U_SEC_BD_WORD9  sec_bd_word9;

    /* word10 */
    U_SEC_BD_WORD10  sec_bd_word10;

    /* word11 */
    U_SEC_BD_WORD11  sec_bd_word11;

    /* word12 */
    U_SEC_BD_WORD12  sec_bd_word12;

    /* word13 */
    U_SEC_BD_WORD13  sec_bd_word13;

    /* word14~15 */
    union {
        uint32_t auth_ivin_addr_l;
        uint32_t tls_1p3_gcm_ivin_l;
    } word14;

    union {
        uint32_t auth_ivin_addr_h;
        uint32_t tls_1p3_gcm_ivin_h;
    } word15;

    /* word16~17 */
    uint32_t auth_key_addr_l;
    uint32_t auth_key_addr_h;

    /* word18~19 */
    uint32_t mac_addr_l;
    uint32_t mac_addr_h;

    /* word20~21 */
    union {
        uint32_t cipher_ivin_addr_l;
        uint32_t tls_1p3_gcm_ivin_h;
    } word20;

    union {
        uint32_t cipher_ivin_addr_h;
        uint32_t tls_1p3_gcm_ivin_vh;
    } word21;

    /* word22~23 */
    uint32_t cipher_key_addr_l;
    uint32_t cipher_key_addr_h;

    /* word24~25 */
    uint32_t data_src_addr_l;
    uint32_t data_src_addr_h;

    /* word26~27 */
    uint32_t data_dst_addr_l;
    uint32_t data_dst_addr_h;

    /* word28 */
    U_SEC_BD_WORD28  sec_bd_word28;

    /* word29 */
    U_SEC_BD_WORD29  sec_bd_word29;

    /* word30 */
    U_SEC_BD_WORD30  sec_bd_word30;

    /* word31 */
    uint32_t counter;
} SEC_BD_S;

/* Define the union U_SEC_BD_PACKET_OST_CFG
*/
typedef union {
    /* Define the struct bits */
    struct {
        uint32_t    sec_bd_rd_ost_cfg     : 8   ; /* [7..0]  */
        uint32_t    reserved_0            : 24  ; /* [31..8]  */
    } bits;

    /* Define an unsigned member */
    uint32_t    status;
} U_SEC_BD_PACKET_OST_CFG ;

/* Define the union U_SEC_MEM_START_INIT
*/
typedef union {
    /* Define the struct bits */
    struct {
        uint32_t    mem_start_init        : 1   ; /* [0]  */
        uint32_t    reserved_0            : 31  ; /* [31..1]  */
    } bits;

    /* Define an unsigned member */
    uint32_t    status;
} U_SEC_MEM_START_INIT ;

/* Define the union U_SEC_MEM_INIT_DONE
*/
typedef union {
    /* Define the struct bits */
    struct {
        uint32_t    mem_init_done        : 1   ; /* [0]  */
        uint32_t    reserved_0           : 31  ; /* [31..1]  */
    } bits;

    /* Define an unsigned member */
    uint32_t    status;
} U_SEC_MEM_INIT_DONE;

/* Define the union U_SEC_CNT_CLR_CE_REG
*/
typedef union {
    /* Define the struct bits */
    struct {
        uint32_t    sec_cnt_clr_ce        : 1   ; /* [0]  */
        uint32_t    reserved_0            : 31  ; /* [31..1]  */
    } bits;

    /* Define an unsigned member */
    uint32_t    status;
} U_SEC_CNT_CLR_CE_REG;

/* Define the union U_BDF_EN_STATUS
*/
typedef union {
    /* Define the struct bits */
    struct {
        uint32_t    bdf_en_status         : 1   ; /* [0]  */
        uint32_t    reserved_0            : 31  ; /* [31..1]  */
    } bits;

    /* Define an unsigned member */
    uint32_t    status;
} U_BDF_EN_STATUS;

/* Define the union U_ACC_STREAMID_S
*/
typedef union {
    /* Define the struct bits */
    struct {
        uint32_t    streamid_s        : 32   ; /* [31..0]  */
    } bits;

    /* Define an unsigned member */
    uint32_t    status;
} U_ACC_STREAMID_S;


/* Define the union U_SEC_BDF_CFG_PD_TAG
*/
typedef union {
    /* Define the struct bits */
    struct {
        uint32_t    bdf_pd_tag        : 24   ; /* [23..0]  */
        uint32_t    reserved_0        : 8   ; /* [31..24]  */
    } bits;

    /* Define an unsigned member */
    uint32_t    status;
} U_SEC_BDF_CFG_PD_TAG;

/* Define the union U_SEC_BDF_CNT_CLR_CE
*/
typedef union {
    /* Define the struct bits */
    struct {
        uint32_t    sec_cnt_clr_ce        : 1   ; /* [0]  */
        uint32_t    reserved_0        : 31   ; /* [31..1]  */
    } bits;

    /* Define an unsigned member */
    uint32_t    status;
} U_SEC_BDF_CNT_CLR_CE;

/* Define the union U_KM_AUTO_REQ_START
*/
typedef union {
    /* Define the struct bits */
    struct {
        uint32_t    km_key_auto_req            : 1   ;
        uint32_t    km_key_auto_req_cmd        : 4   ;
        uint32_t    reserved_0                 : 27  ;
    } bits;

    /* Define an unsigned member */
    uint32_t    status;
} U_KM_AUTO_REQ_START;

/* Define the union U_KM_AUTO_REQ_DONE
*/
typedef union {
    /* Define the struct bits */
    struct {
        uint32_t    km_key_auto_done          : 1   ;
        uint32_t    km_key_auto_doing         : 1   ;
        uint32_t    km_key_auto_fail          : 1   ;
        uint32_t    reserved_0                : 29  ;
    } bits;

    /* Define an unsigned member */
    uint32_t    status;
} U_KM_AUTO_REQ_DONE;


/* Define the union U_KM_REQ_START
*/
typedef union {
    /* Define the struct bits */
    struct {
        uint32_t    km_key_req            : 1   ;
        uint32_t    km_key_req_cmd        : 4   ;
        uint32_t    reserved_0            : 27  ;
    } bits;

    /* Define an unsigned member */
    uint32_t    status;
} U_KM_REQ_START;

/* Define the union U_KM_REQ_DONE_REG
*/
typedef union {
    /* Define the struct bits */
    struct {
        uint32_t    km_key_done        : 1   ;
        uint32_t    km_key_fail        : 1   ;
        uint32_t    km_key_doing       : 1   ;
        uint32_t    km_key_read_cmd    : 4   ;
        uint32_t    reserved_0         : 25  ;
    } bits;

    /* Define an unsigned member */
    uint32_t    status;
} U_KM_REQ_DONE_REG;

typedef union {
    /* Define the struct bits */
    struct {
        uint32_t    bdf_fifo_empty        : 1   ; /* [0]  */
        uint32_t    bdf_fifo_afull        : 1   ; /* [1]  */
        uint32_t    bdf_fifo_full         : 1   ; /* [2]  */
        uint32_t    reserved_0            : 29  ; /* [31..3]  */
    } bits;

    /* Define an unsigned member */
    uint32_t    status;
} U_SEC_BDF_FIFO_STATUS;


typedef union {
    /* Define the struct bits */
    struct {
        uint32_t    bdf_push_en           : 1   ; /* [0]  */
        uint32_t    bdf_pop_en            : 1   ; /* [1]  */
        uint32_t    reserved_0            : 30  ; /* [31..2]  */
    } bits;

    /* Define an unsigned member */
    uint32_t    status;
} U_SEC_BDF_EN;

#endif
