/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: tee drv module id
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#ifndef __HI_TEE_DRV_MODULE_ID_H
#define __HI_TEE_DRV_MODULE_ID_H

/* Module ID */
typedef enum {
    /* common */ /* CNcomment: 系统通用模块 */
    HI_ID_SYS = 0x00,
    HI_ID_MODULE,
    HI_ID_LOG,
    HI_ID_PROC,
    HI_ID_MEM,
    HI_ID_STAT,
    HI_ID_PDM,
    HI_ID_MEMDEV,
    HI_ID_MDDRC,
    HI_ID_MAILBOX,
    HI_ID_RM,      /* Resource management */
    HI_ID_PM,      /* Power management */
    HI_ID_DVFS,
    HI_ID_RUNTIME, /* Run time check */
    HI_ID_SPREAD,
    HI_ID_CUSTOM,  /* Customize */

    /* Peripheral */ /* CNcomment: 外设相关模块 */
    HI_ID_FLASH = 0x10,
    HI_ID_IR,
    HI_ID_I2C,
    HI_ID_GPIO,
    HI_ID_GPIO_I2C,
    HI_ID_PWM,
    HI_ID_LSADC,
    HI_ID_SPI,
    HI_ID_KEYLED,
    HI_ID_WDG,
    HI_ID_CI,
    HI_ID_SCI,
    HI_ID_BEIDOU,
    HI_ID_BT,
    HI_ID_FRONTEND,

    /* Demux */ /* CNcomment: 解复用相关模块 */
    HI_ID_DEMUX = 0x2c,

    /* Security */ /* CNcomment: 安全相关模块 */
    HI_ID_OTP = 0x30,
    HI_ID_KLAD,
    HI_ID_KEYSLOT,
    HI_ID_CIPHER,
    HI_ID_TSR2RCIPHER,
    HI_ID_CERT,
    HI_ID_TSIO,
    HI_ID_SSM,
    HI_ID_VMX_ULTRA,
    HI_ID_CASIMAGE,
    HI_ID_HDCP,
    HI_ID_TALOAD,

    /* Audio */ /* CNcomment: 音频相关模块 */
    HI_ID_SIF = 0x40,
    HI_ID_AIAO,
    HI_ID_AI,
    HI_ID_AENC,
    HI_ID_ADEC,
    HI_ID_AFLT, /* HIFI */
    HI_ID_ADSP,
    HI_ID_TTS,
    HI_ID_AO,
    HI_ID_AMP,

    /* Video and input/output */ /* CNcomment: 视频及输入输出相关模块 */
    HI_ID_VFE = 0x50,
    HI_ID_TVD,
    HI_ID_HDDEC,
    HI_ID_VBI,
    HI_ID_VICAP,
    HI_ID_VI,
    HI_ID_VENC,
    HI_ID_VFMW,
    HI_ID_VDEC,
    HI_ID_PQ,
    HI_ID_MEMC,
    HI_ID_FRC,
    HI_ID_VPSS,
    HI_ID_VPLUGIN,
    HI_ID_WIN,
    HI_ID_DISP,
    HI_ID_HDMIRX,
    HI_ID_HDMITX,
    HI_ID_PANEL,
    HI_ID_MIPI,
    HI_ID_FDMNG, /* 3D detect */
    HI_ID_DISPMNG,
    HI_ID_DISPCTRL,

    HI_ID_OMXVENC = 0x6A,
    HI_ID_OMXVDEC = 0x6B,

    /* Graphics */ /* CNcomment: 图形相关模块 */
    HI_ID_FB = 0x70,
    HI_ID_GPU,
    HI_ID_TDE,
    HI_ID_GFX2D,
    HI_ID_JPGDEC,
    HI_ID_JPGENC,
    HI_ID_PNG,
    HI_ID_HIGO,

    /* Player */ /* CNcomment: 播放器相关模块 */
    HI_ID_AVPLAY = 0x80,
    HI_ID_SYNC,
    HI_ID_VSYNC,
    HI_ID_ASYNC,
    HI_ID_PVR,

    /* Component */ /* CNcomment: 组件相关模块 */
    HI_ID_SUBT = 0x90,
    HI_ID_TTX,
    HI_ID_CC,
    HI_ID_LOADER,
    HI_ID_KARAOKE,
    HI_ID_VP,
    HI_ID_DEMO,

    /* Middleware */ /* CNcomment: 中间件相关模块 */
    HI_ID_NETFLIX = 0xA0,

    /* NPU */ /* CNcomment: NPU相关模块 */
    HI_ID_NPU = 0xB0,

    /* User definition */ /* CNcomment: 为上层应用保留的自定义区 */
    HI_ID_USR = 0xC0,

    HI_ID_MAX = 0xFF
} hi_mod_id;

typedef struct {
    unsigned long long arg0;
    unsigned long long arg1;
    unsigned long long arg2;
    unsigned long long arg3;
    unsigned long long arg4;
    unsigned long long arg5;
    unsigned long long arg6;
    unsigned long long arg7;
} hi_tee_ioctl_args;

#ifdef CFG_HI_TEE_DEMO_SUPPORT
#define  TEE_DEMO_IOCTL_HELLO                           0x1
#endif

#ifdef CFG_HI_TEE_VFMW_SUPPORT
#define TEE_VFMW_IOCTL_INIT                             0x1
#define TEE_VFMW_IOCTL_EXIT                             0x2
#define TEE_VFMW_IOCTL_RESUME                           0x3
#define TEE_VFMW_IOCTL_SUSPEND                          0x4
#define TEE_VFMW_IOCTL_CONTROL                          0x5
#define TEE_VFMW_IOCTL_THREAD                           0x6
#define TEE_VFMW_IOCTL_GET_IMAGE                        0x7
#define TEE_VFMW_IOCTL_RELEASE_IMAGE                    0x8
#define TEE_VFMW_IOCTL_READ_PROC                        0x9
#define TEE_VFMW_IOCTL_WRITE_PROC                       0xa

#define TEE_VFMW_IOCTL_PARSE_CSD                        0xb
#define TEE_VFMW_IOCTL_CHECK_ADDR                       0xc
#endif

#ifdef CFG_HI_TEE_AVPLAY_SUPPORT
#define TEE_AVPLAY_IOCTL_E2RCOPY                        0x1
#endif

#ifdef CFG_HI_TEE_LOG_SUPPORT
#define TEE_LOG_IOCTL_SETLEVEL                          0x1
#define TEE_LOG_IOCTL_GETLEVEL                          0x2
#endif

#ifdef CFG_HI_TEE_KLAD_SUPPORT
#endif

#ifdef CFG_HI_TEE_KEYSLOT_SUPPORT
#endif

#ifdef CFG_HI_TEE_OTP_SUPPORT
#endif

#ifdef CFG_HI_TEE_DEMUX_SUPPORT
#define TEE_DEMUX_IOCTL_NEW_DESC                        0x1
#define TEE_DEMUX_IOCTL_DEL_DESC                        0x2
#define TEE_DEMUX_IOCTL_ATTACH_DESC                     0x3
#define TEE_DEMUX_IOCTL_DETACH_DESC                     0x4
#define TEE_DEMUX_IOCTL_GET_DESC_ATTR                   0x5
#define TEE_DEMUX_IOCTL_SET_DESC_ATTR                   0x6
#define TEE_DEMUX_IOCTL_SET_DESC_EVEN                   0x7
#define TEE_DEMUX_IOCTL_SET_DESC_ODD                    0x8
#define TEE_DEMUX_IOCTL_SET_DESC_EVEN_IV                0x9
#define TEE_DEMUX_IOCTL_SET_DESC_ODD_IV                 0xa
#define TEE_DEMUX_IOCTL_GET_KEYID                       0xb
#define TEE_DEMUX_IOCTL_NEW_SC                          0xc
#define TEE_DEMUX_IOCTL_DEL_SC                          0xd
#define TEE_DEMUX_IOCTL_GET_SC_ATTR                     0xe
#define TEE_DEMUX_IOCTL_SET_SC_ATTR                     0xf
#define TEE_DEMUX_IOCTL_SET_SC_EVEN                     0x10
#define TEE_DEMUX_IOCTL_SET_SC_ODD                      0x11
#define TEE_DEMUX_IOCTL_ATTACH_SC                       0x12
#define TEE_DEMUX_IOCTL_DETACH_SC                       0x13
#define TEE_DEMUX_IOCTL_GET_SC_KEYID                    0x14
#define TEE_DEMUX_IOCTL_GET_CHNID                       0x15
#define TEE_DEMUX_IOCTL_GET_CAP                         0x16
#define TEE_DEMUX_IOCTL_REG_CHAN                        0x17
#define TEE_DEMUX_IOCTL_UNREG_CHAN                      0x18
#define TEE_DEMUX_IOCTL_REG_OQ                          0x19
#define TEE_DEMUX_IOCTL_UNREG_OQ                        0x1a
#define TEE_DEMUX_IOCTL_REG_RAM_PORT                    0x1b
#define TEE_DEMUX_IOCTL_UNREG_RAM_PORT                  0x1c
#define TEE_DEMUX_IOCTL_LOCK_CHAN                       0x1d
#define TEE_DEMUX_IOCTL_UNLOCK_CHAN                     0x1e
#define TEE_DEMUX_IOCTL_REG_VID_SECBUF                  0x1f
#define TEE_DEMUX_IOCTL_UNREG_VID_SECBUF                0x20
#define TEE_DEMUX_IOCTL_REG_AUD_SECBUF                  0x21
#define TEE_DEMUX_IOCTL_UNREG_AUD_SECBUF                0x22
#define TEE_DEMUX_IOCTL_FIXUP_AUD_SECBUF                0x23
#define TEE_DEMUX_IOCTL_PARSER_PES_HEADER               0x24
#define TEE_DEMUX_IOCTL_PARSER_DISP_CONTROL             0x25
#define TEE_DEMUX_IOCTL_GET_PES_HEADER_LEN              0x26
#define TEE_DEMUX_IOCTL_REG_REC_SECBUF                  0x27
#define TEE_DEMUX_IOCTL_UNREG_REC_SECBUF                0x28
#define TEE_DEMUX_IOCTL_FIXUP_HEVC_INDEX                0x29
#define TEE_DEMUX_IOCTL_REG_SECTION_SECBUF              0x2a
#define TEE_DEMUX_IOCTL_UNREG_SECTION_SECBUF            0x2b
#define TEE_DEMUX_IOCTL_FIXUP_SECTION_SECBUF            0x2c
#define TEE_DEMUX_IOCTL_CHECK_REC_SECBUF_ADDR           0x2d
#define TEE_DEMUX_IOCTL_DESCRAMBLER_NONSEC_KEY_ACQUIRE  0x2e
#define TEE_DEMUX_IOCTL_DESCRAMBLER_NONSEC_KEY_RELEASE  0x2f
#define TEE_DEMUX_IOCTL_ATTACH_RAM_PORT                 0x30
#define TEE_DEMUX_IOCTL_DETACH_RAM_PORT                 0x31
#define TEE_DEMUX_IOCTL_CHECK_TS_SECBUF_ADDR            0x32
#define TEE_DEMUX_IOCTL_SET_SECTS_TO_SECREC             0x33
#define TEE_DEMUX_IOCTL_INIT                            0x34
#define TEE_DEMUX_IOCTL_DEINIT                          0x35
#endif

#ifdef CFG_HI_TEE_COMMON_SUPPORT
#define TEE_COMMON_IOCTL_GET_VERSION_INFO               0X1
#define TEE_COMMON_IOCTL_NAGRA_TA_PRINT                 0X2
#endif

#ifdef CFG_HI_TEE_VMX_ULTRA_SUPPORT
#define TEE_VMX_ULTRA_IOCTL_INIT_RESOURCE                     0x1
#define TEE_VMX_ULTRA_IOCTL_DEINIT_RESOURCE                   0x2
#define TEE_VMX_ULTRA_IOCTL_GET_RESOURCE                      0x3
#define TEE_VMX_ULTRA_IOCTL_UPDATE_TA_PARAM                   0x4
#define TEE_VMX_ULTRA_IOCTL_INSTALL_CALLBACK                  0x5
#define TEE_VMX_ULTRA_IOCTL_CALLBACK                          0x6
#define TEE_VMX_ULTRA_IOCTL_FORMAT_INPUT_EXTEND_INFO          0x7
#define TEE_VMX_ULTRA_IOCTL_FORMAT_OUTPUT_EXTEND_INFO         0x8
#define TEE_VMX_ULTRA_IOCTL_RELEASE_MODULE_RESOURCE           0x9
#define TEE_VMX_ULTRA_IOCTL_INIT_AGENT_PARAM                  0xa
#define TEE_VMX_ULTRA_IOCTL_DEINIT_AGENT_PARAM                0xb
#define TEE_VMX_ULTRA_IOCTL_UPDATE_AGENT_PARAM                0xc
#define TEE_VMX_ULTRA_IOCTL_GET_TA_PARAM                      0xd
#define TEE_VMX_ULTRA_IOCTL_TEST_EXT_COPY                     0xe
#define TEE_VMX_ULTRA_IOCTL_INIT_MULT_CIHPHER_RESOURCE        0xf
#define TEE_VMX_ULTRA_IOCTL_INIT_EVEN_TAIL_CIHPHER_RESOURCE   0x10
#define TEE_VMX_ULTRA_IOCTL_FORMAT_MULT_CIPHER_INPUT          0x11
#define TEE_VMX_ULTRA_IOCTL_DEINIT_MULT_CIHPHER_RESOURCE      0x12
#define TEE_VMX_ULTRA_IOCTL_DEINIT_EVEN_TAIL_CIHPHER_RESOURCE 0x13
#define TEE_VMX_ULTRA_IOCTL_INIT_ODD_TAIL_CIHPHER_RESOURCE    0x14
#define TEE_VMX_ULTRA_IOCTL_DEINIT_ODD_TAIL_CIHPHER_RESOURCE  0x15
#define TEE_VMX_ULTRA_IOCTL_INIT_FRAME_HANOI_RESOURCE         0x16
#define TEE_VMX_ULTRA_IOCTL_DEINIT_FRAME_HANOI_RESOURCE       0x17
#define TEE_VMX_ULTRA_IOCTL_INIT_TA_CONTENT                   0x18
#define TEE_VMX_ULTRA_IOCTL_DEINIT_TA_CONTENT                 0x19
#define TEE_VMX_ULTRA_IOCTL_UPDATE_TA_CONTENT                 0x1a
#define TEE_VMX_ULTRA_IOCTL_MUTEX_LOCK                        0x1b
#define TEE_VMX_ULTRA_IOCTL_MUTEX_UNLOCK                      0x1c
#define TEE_VMX_ULTRA_IOCTL_GET_EXTEND_INFO_R2R               0x1d
#define TEE_VMX_ULTRA_IOCTL_UPDATE_EXTEND_INFO_R2R            0x1e
#define TEE_VMX_ULTRA_IOCTL_GET_TA_PARAM_BY_UUID              0x1f
#define TEE_VMX_ULTRA_IOCTL_GET_EXTEND_RESOURCE               0x20
#define TEE_VMX_ULTRA_IOCTL_UPDATE_EXTEND_RESOURCE            0x21
#define TEE_VMX_ULTRA_IOCTL_UPDATE_TA_SERVICE_INFO            0x22
#define TEE_VMX_ULTRA_IOCTL_GET_TA_SERVICE_INFO               0x23
#define TEE_VMX_ULTRA_IOCTL_UPDATE_EXT_FRAME_INFO             0x24
#endif

#endif /* __HI_TEE_DRV_MODULE_ID_H */
