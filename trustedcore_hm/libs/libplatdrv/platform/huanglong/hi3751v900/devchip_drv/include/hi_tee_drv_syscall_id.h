/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: tee drv syscall id
 * Author: Hisilicon
 * Create: 2017-06-17
 * NOTE: all the id cannot be same, and all id must be in 0xF000 ~ 0xFFFF. every
 * moudle has max 64 ids, for example, drv demo syscall id is from 0xF000 to 0xF03F.
 * If 64 ids are not enough for one moudle, it can be expanded to 128 ids, but it
 * must note the range.
 */

#ifndef __HI_TEE_DRV_SYSCALL_ID_H
#define __HI_TEE_DRV_SYSCALL_ID_H

#define  HI_TEE_SYSCALL_HISILICON_IOCTL   0xEFFF

#ifdef CFG_HI_TEE_DEMO_SUPPORT
/* 0xF000 ~ 0xF03F */
#define  HI_TEE_SYSCALL_DEMO_HELLO        0xF000
#define  HI_TEE_SYSCALL_DEMO_FUNC_TEST    0xF001
#endif

#ifdef CFG_HI_TEE_SSM_SUPPORT
/* 0xF040 ~ 0xF07F */
#define  HI_TEE_SYSCALL_SSM_CREATE         0xF040
#define  HI_TEE_SYSCALL_SSM_DESTROY        0xF041
#define  HI_TEE_SYSCALL_SSM_ADD_RESOURCE   0xF042
#define  HI_TEE_SYSCALL_SSM_ATTACH_BUF     0xF043
#define  HI_TEE_SYSCALL_SSM_GET_INTENT     0xF044
#define  HI_TEE_SYSCALL_SSM_IOMMU_CONFIG   0xF045
#define  HI_TEE_SYSCALL_SSM_SET_UUID       0xF046
#define  HI_TEE_SYSCALL_SSM_CHECK_UUID     0xF047
#define  HI_TEE_SYSCALL_SSM_CHECK_BUF      0xF048
#define  HI_TEE_SYSCALL_SSM_INIT           0xF049
#define  HI_TEE_SYSCALL_SSM_SEND_POLICY    0xF04A
#define  HI_TEE_SYSCALL_SSM_SET_REG        0xF04B
#endif

#ifdef CFG_HI_TEE_DEMUX_SUPPORT
/* 0xF080 ~ 0xF0FF for demux */
#define  SYSCALL_DMX_BASE                  0xF080
#define  SYSCALL_DMX_END                   0xF0FF
#define  HI_TEE_SYSCALL_DMX                0xF080
#endif

#ifdef CFG_HI_TEE_CIPHER_SUPPORT
/* 0xF100 ~ 0xF13F for demux */
#define  HI_TEE_SYSCALL_CIPHER             0xF100
#endif

#ifdef CFG_HI_TEE_OTP_SUPPORT
/* 0xF140 ~ 0xF17F for OTP */
#define CMD_OTP_PROCESS                     0xF140
#endif

#ifdef CFG_HI_TEE_KEYSLOT_SUPPORT
/* 0xF180 ~ 0xF1BF for KEYSLOT */
#define CMD_KS_PROCESS                     0xF180
#endif

#ifdef CFG_HI_TEE_KLAD_SUPPORT
/* 0xF1C0 ~ 0xF1FF for KLAD */
#define CMD_KLAD_PROCESS                   0xF1C0
#endif

#ifdef CFG_HI_TEE_VFMW_SUPPORT
/* 0xF200 ~ 0xF23F for vfmw */
#define  HI_TEE_SYSCALL_VFMW_LOAD          0xF200
#define  HI_TEE_SYSCALL_VFMW_UNLOAD        0xF201
#define  HI_TEE_SYSCALL_VFMW_RELOAD        0xF202
#define  HI_TEE_SYSCALL_VFMW_CMD           0xF203
#define  HI_TEE_SYSCALL_VFMW_MAX           0xF23F
#endif

/* 0xF240 ~ 0xF27F for mem */
#define HI_TEE_SYSCALL_SMMU_ID             0xF260
#define HI_TEE_SYSCALL_MMZ_ID              0xF270
#define HI_TEE_SYSCALL_SMMUAGENT_ID        0xF271

#ifdef CFG_HI_TEE_LOG_SUPPORT
/* 0xF280 ~ 0xF2BF for log */
#define HI_TEE_SYSCALL_LOG                 0xF280
#endif

#ifdef CFG_HI_TEE_COMMON_SUPPORT
/* 0xF2C0 ~ 0xF2FF for common */
#define HI_TEE_SYSCALL_COMMON              0xF2C0
#endif

#ifdef CFG_HI_TEE_TSR2RCIPHER_SUPPORT
/* 0xF300 ~ 0xF33F for tsr2rcipher */
#define HI_TEE_SYSCALL_TSR2RCIPHER         0xF300
#endif

#ifdef CFG_HI_TEE_PVR_SUPPORT
/* 0xF340 ~ 0xF37F for pvr */
#define HI_TEE_SYSCALL_PVR                 0xF340
#endif

#ifdef HI_TEE_KLAD_CERT
#define CMD_CERT_PROCESS                   0xF380
#endif

#ifdef CFG_HI_TEE_DYNAMIC_TA_LOAD
#define HI_TEE_SYSCALL_TALOAD              0xF3C0
#endif

#ifdef CFG_HI_TEE_HDMITX_SUPPORT
/* 0xF400 ~ 0xF47F for HDMITX */
#define HI_TEE_SYSCALL_HDMITX              0xF400
#endif

#ifdef CFG_HI_TEE_HDMIRX_SUPPORT
/* 0xF480 ~ 0xF4BF for HDMIRX */
#define HI_TEE_SYSCALL_HDMIRX              0xF480
#endif

#ifdef CFG_HI_TEE_NPU_SUPPORT
/* 0xF4C0 ~ 0xF4EF for NPU */
#define HI_TEE_SYSCALL_NPU                0xF4C0
#endif

#endif /* __HI_TEE_DRV_SYSCALL_ID_H */
