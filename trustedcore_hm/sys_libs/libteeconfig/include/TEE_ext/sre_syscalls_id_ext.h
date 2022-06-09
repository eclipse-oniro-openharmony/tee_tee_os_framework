/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: sre syscalls implementation
 * Create: 2018-05-18
 */
#ifndef __SRE_SYSCASLLS_ID_EXT_H__
#define __SRE_SYSCASLLS_ID_EXT_H__

/*
 * 0x9800 - 0x980f are reserved for driver (MDRV_MODULE_ID in drv_call.h)
 * cannot use those cmd id when add new command
 */
/* efuse */
#define SW_SYSCALL_EFUSE_READ         0xc0ec
#define SW_SYSCALL_TEE_HAL_GET_DIEID  0xc0ed
#define SW_SYSCALL_EFUSE_WRITE        0xc0f0
#define SW_SYSCALL_P61_FAC_TEST       0xd0fe
#define SW_SYSCALL_DRIVER_TEST        0xd0ff
#define SW_SYSCALL_SCARD_CONNECT      0xe108
#define SW_SYSCALL_SCARD_DISCONNECT   0xe109
#define SW_SYSCALL_SCARD_TRANSMIT     0xe10a
#define SW_SYSCALL_SCARD_SUPPORT_MODE 0xe10b
#define SW_SYSCALL_SCARD_SEND         0xe10c
#define SW_SYSCALL_SCARD_RECEIVE      0xe10d
#define SW_SYSCALL_SCARD_GET_STATUS   0xe10e
#define SW_SYSCALL_SE_CONNECT       0xe10f
#define SW_SYSCALL_SE_DISCONNECT    0xe110
#define SW_SYSCALL_ESE_TRANSMIT       0xe111
#define SW_SYSCALL_ESE_READ           0xe112
#define SW_SYSCALL_SCARD_GET_ESE_TYPE 0xe113
#define SW_SYSCALL_ESE_7816_RESET     0xe114
#define SW_SYSCALL_ESE_GET_OS_MODE    0xe115
#define SW_SYSCALL_SET_NFC_TYPE       0xe116

/*  MSPCore 0xe130 - 0xe14f */
#define SW_SYSCALL_MSPC_FACOTRY_CMD         0xe131
#define SW_SYSCALL_MSPC_POWER_ON            0xe132
#define SW_SYSCALL_MSPC_POWER_OFF           0xe133
#define SW_SYSCALL_MSPC_IPC_TEST            0xe134
#define SW_SYSCALL_MSPC_DDR_READ            0xe135
#define SW_SYSCALL_MSPC_DDR_WRITE           0xe136

/* HiSE 0xe150 - 0xe16f */
#define SW_SYSCALL_SEPLAT_GET_DTS_STATUS    0xe150
#define SW_SYSCALL_SEPLAT_POWER_CTRL        0xe151

/* cambricon */
#define SW_SYSCALL_CAMBRICON_CFG 0xe800

/* NPU sec 0x9110--0x912f */
#define SW_SYSCALL_NPU_IOCTL_CFG         0x9110
#define SW_SYSCALL_NPU_OPEN_MODE_CFG     0x9111
#define SW_SYSCALL_NPU_REALEASE_MODE_CFG 0x9112

#define SW_SYSCALL_NPU_LLSEEK_CFG      0x9113
#define SW_SYSCALL_NPU_WRITE_INSTR_CFG 0x9114
#define SW_SYSCALL_NPU_SENSORHUB_IPC   0x9115

#define SW_SYSCALL_NPU_SMMU_SVM 0x9116
#define SW_SYSCALL_NPU_MESP_DECRYPT 0x9117

/* hdcp */
#define SW_SYSCALL_HDCP13_KEY_ALL_SET 0x9100
#define SW_SYSCALL_HDCP22_KEY_SET     0x9104
#define SW_SYSCALL_HDCP_DP_ENABLE     0x9108
#define SW_SYSCALL_HDCP_GET_VALUE     0x9109
#define SW_SYSCALL_HDCP_SET_REG       0x910a
#define SW_SYSCALL_HDCP_IOCTL         0x910b
#define SW_SYSCALL_HDCP_WFD_HANDLE_MAP   0x910c
#define SW_SYSCALL_HDCP_WFD_HANDLE_UNMAP 0x910d

/* get share memory info with fastboot */
#define SW_SYSCALL_GET_SHAREMEM_INFO 0xe410

/* tui sys call id scope : 0xe500   ----   0xe5ff  */
enum tui_sw_syscall_id {
    SW_SYSCALL_TUI_BASE = 0xe500,

    /* display driver syscall id */
    SW_SYSCALL_FB_SEC_CFG,      /* 0xe501 */
    SW_SYSCALL_FB_SEC_DISPLAY,  /* 0xe502 */
    SW_SYSCALL_FB_ACTIVE_FLAG,  /* 0xe503 */
    SW_SYSCALL_FB_GETINFO,      /* 0xe504 */
    SW_SYSCALL_FB_RELEASE_FLAG, /* 0xe505 */
    SW_SYSCALL_FB_SEC_SET,      /* 0xe506 */

    /* tui driver syscall id */
    SW_SYSCALL_TUI_TIMER_CREATE,  /* 0xe507 */
    SW_SYSCALL_TUI_TIMER_DELETE,  /* 0xe508 */
    SW_SYSCALL_TUI_TIMER_ENABLE,  /* 0xe509 */
    SW_SYSCALL_TUI_TIMER_START,   /* 0xe50a */
    SW_SYSCALL_GET_TTF_MEM,       /* 0xe50b */
    SW_SYSCALL_MAP_TTF_MEM,       /* 0xe50c */
    SW_SYSCALL_UNMAP_TTF_MEM,     /* 0xe50d */
    SW_SYSCALL_INIT_TTF_MEM,      /* 0xe50e */
    SW_SYSCALL_UNINIT_TTF_MEM,    /* 0xe50f */
    SW_SYSCALL_TS_IOCTL,          /* 0xe510 */
    SW_SYSCALL_TUI_CONFIG,        /* 0xe511 */
    SW_SYSCALL_TUI_DECONFIG,      /* 0xe512 */
    SW_SYSCALL_SET_NOTCH_SIZE,    /* 0xe513 */
    SW_SYSCALL_GET_NOTCH_SIZE,    /* 0xe514 */
    SW_SYSCALL_TUI_DIALOG,        /* 0xe515 */
    SW_SYSCALL_GET_CUR_PANEL,     /* 0xe516 */
    SW_SYSCALL_SET_FOLD_SCREEN,   /* 0xe517 */
    SW_SYSCALL_GET_FOLD_SCREEN,   /* 0xe518 */
    SW_SYSCALL_TUI_TP_SLIDE_MODE, /* 0xe519 */
    SW_SYSCALL_TL_FLAG_RESET,     /* 0xe51a */
    SW_SYSCALL_TL_START_TIMER,    /* 0xe51b */
    SW_SYSCALL_TL_END_TIMER,      /* 0xe51c */
    SW_SYSCALL_TUI_FB_DISPLAY,    /* 0xe51d */
    SW_SYSCALL_TUI_FB_GETINFO,    /* 0xe51e */
    SW_SYSCALL_TUI_FB_RELEASE,    /* 0xe51f */
    SW_SYSCALL_TUI_TIMER_STOP,    /* 0xe520 */
    SW_SYSCALL_TP_SET_KB_RECT,    /* 0xe521 */
    SW_SYSCALL_GET_HASH_INFO,     /* 0xe522 */
    SW_SYSCALL_PUSH_HASH_INFO,     /* 0xe522 */

    SW_SYSCALL_TUI_MAX,
};

/* vsim */
#define SW_SYSCALL_FP_COMMAND_INFO                                0xe600
#define SW_SYSCALL_FP_SPI_TRANSACTION                             0xe601
#define SW_SYSCALL_FP_SPI_FULL_DUPLEX_WITH_SPEED_TRANSACTION      0xe602
#define SW_SYSCALL_FP_SPI_HALF_DUPLEX_WITH_SPEED_TRANSACTION      0xe603
#define SW_SYSCALL_SRE_GET_RTC_TIME                               0xe604
#define SW_SYSCALL_SRE_SET_RTC_TIME                               0xe605
#define SW_SYSCALL_FP_SPI_DEV2_TRANSACTION                        0xe606
#define SW_SYSCALL_FP_SPI_DEV2_FULL_DUPLEX_WITH_SPEED_TRANSACTION 0xe607
#define SW_SYSCALL_FP_SPI_DEV2_HALF_DUPLEX_WITH_SPEED_TRANSACTION 0xe608
#define  SW_SYSCALL_FP_SET_SPI_MODE                               0xe609

/* vcodec */
#define SW_SYSCALL_SECURE_TEE_GETID       0x9000
#define SW_SYSCALL_SECURE_TEE_RELEASEID   0x9004
#define SW_SYSCALL_SECURE_TEE_SENDMESSAGE 0x9008
#define SW_SYSCALL_SECURE_TEE_MMAP        0x9009
#define SW_SYSCALL_SECURE_TEE_UNMAP       0x900a
#define SW_SYSCALL_SECURE_ISSEUCREMEM     0x900b
#define SW_SYSCALL_SECURE_FLUSH_CACHE     0x900c
#define SW_SYSCALL_BSP_MODEM_CALL         0xe700

#define SW_SYSCALL_FR_SECURE_TEE_MMAP     0xe800
#define SW_SYSCALL_FR_SECURE_TEE_UNMAP    0xe801
#define SW_SYSCALL_FR_SECURE_ISSECUREMEM  0xe802
#define SW_SYSCALL_FR_SECURE_FLUSH_CACHE  0xe803
#define SW_SYSCALL_FR_SECURE_ION_SET      0xe804
#define SW_SYSCALL_FR_SECURE_ION_UNSET    0xe805
#define SW_SYSCALL_FR_READ_CURRENT_TIME   0xe806
#define SW_SYSCALL_FR_GET_STATIC_PHY_ADDR 0xe807

#ifdef TEE_SUPPORT_HIVCODEC
/* hi_vcodec */
#define SW_SYSCALL_SEC_VDEC_INIT       0xb000
#define SW_SYSCALL_SEC_VDEC_EXIT       0xb004
#define SW_SYSCALL_SEC_VDEC_CONTROL    0xb008
#define SW_SYSCALL_SEC_VDEC_SUSPEND    0xb00c
#define SW_SYSCALL_SEC_VDEC_RESUME     0xb010
#define SW_SYSCALL_SEC_VDEC_RUNPROCESS 0xb014
#ifdef VCODEC_ENG_VERSION
#define SW_SYSCALL_SEC_VDEC_READPROC  0xb018
#define SW_SYSCALL_SEC_VDEC_WRITEPROC 0xb01c
#endif
#define SW_SYSCALL_SEC_VDEC_GETCHANIMAGE      0xb020
#define SW_SYSCALL_SEC_VDEC_RELEASECHANIMAGE  0xb024
#define SW_SYSCALL_SEC_VDEC_CONFIGINPUTBUFFER 0xb025
#define SW_SYSCALL_SEC_VENC_MEMREE2TEE        0xb026
#define SW_SYSCALL_SEC_VENC_MEMTEE2REE        0xb027
#define SW_SYSCALL_SEC_VENC_CFG_MASTER        0xb028
#define SW_SYSCALL_SEC_VENC_RESET_MASTER      0xb029

#define SW_SYSCALL_SEC_VDEC_DRV_INIT           0xb030
#define SW_SYSCALL_SEC_VDEC_DRV_EXIT           0xb031
#define SW_SYSCALL_SEC_VDEC_DRV_SCD_START      0xb032
#define SW_SYSCALL_SEC_VDEC_DRV_IOMMU_MAP      0xb033
#define SW_SYSCALL_SEC_VDEC_DRV_IOMMU_UNMAP    0xb034
#define SW_SYSCALL_SEC_VDEC_DRV_GET_ACTIVE_REG 0xb035
#define SW_SYSCALL_SEC_VDEC_DRV_DEC_START      0xb036
#define SW_SYSCALL_SEC_VDEC_DRV_IRQ_QUERY      0xb037
#define SW_SYSCALL_SEC_VDEC_DRV_SET_DEV_REG    0xb044
#define SW_SYSCALL_SEC_VDEC_DRV_RESUME         0xb045
#define SW_SYSCALL_SEC_VDEC_DRV_SUSPEND        0xb046
#endif

#ifdef FEATURE_IRIS
/* iris */
#define SW_SYSCALL_IRIS_TEE_MMAP           0xe610
#define SW_SYSCALL_IRIS_TEE_UNMAP          0xe614
#define SW_SYSCALL_IRIS_TEE_ISSECUREMEMORY 0xe618
#endif

#ifdef TEE_SUPPORT_TZMP2
#define SW_SYSCALL_SECMEM_ION_IOCTL_SECTA 0xe620
#define SW_SYSCALL_SECMEM_ION_MMAP        0xe621
#define SW_SYSCALL_SECMEM_ION_MUNMAP      0xe622
#define SW_SYSCALL_SECMEM_DDR_CFG         0xe623
#define SW_SYSCALL_SECMEM_ION_MMAP_SFD    0xe624
#define SW_SYSCALL_SECMEM_ION_MUNMAP_SFD  0xe625
#define SW_SYSCALL_SECMEM_DDR_CFG_SFD     0xe626
#define SW_SYSCALL_SECMEM_CREATE_DOMAIN   0xe627
#define SW_SYSCALL_SECMEM_DESTROY_DOMAIN  0xe628
#endif

#ifdef TEE_SUPPORT_SECISP
#define SW_SYSCALL_SECISP_DISRESET         0xe710
#define SW_SYSCALL_SECISP_RESET            0xe711
#define SW_SYSCALL_SECISP_NONSEC_MEM_MAP   0xe712
#define SW_SYSCALL_SECISP_NONSEC_MEM_UNMAP 0xe713
#define SW_SYSCALL_SECISP_SEC_MEM_MAP      0xe714
#define SW_SYSCALL_SECISP_SEC_MEM_UNMAP    0xe715
#define SW_SYSCALL_SECISP_MEM_CFG          0xe716
#define SW_SYSCALL_SECISP_MEM_END          0xe717
#endif

/* ivp system call id 0xe050-0xe06f */
#ifdef TEE_SUPPORT_SECIVP
#define SW_SYSCALL_SECIVP_SEC_MEM_MAP      0xe050
#define SW_SYSCALL_SECIVP_SEC_MEM_UNMAP    0xe051
#define SW_SYSCALL_SECIVP_SEC_NONMEM_MAP   0xe052
#define SW_SYSCALL_SECIVP_SEC_NONMEM_UNMAP 0xe053
#define SW_SYSCALL_SECIVP_SMMU_ON          0xe054
#define SW_SYSCALL_SECIVP_SMMU_OFF         0xe055
#define SW_SYSCALL_SECIVP_SEC_BIND         0xe056
#define SW_SYSCALL_SECIVP_SEC_UNBIND       0xe057
#endif

#ifdef FEATURE_SE
#define SW_SYSCALL_SE_SETFLAG 0xe910
#define SW_SYSCALL_SE_GETFLAG 0xe911
#endif

#ifdef TEE_SUPPORT_FILE_ENCRY
#define SW_SYSCALL_FILE_ENCRY_INTERFACE 0x9130
#endif

/* secboot */
#define SW_COPY_IMG_FROM_OS_DRIVER 0xe009

/* GP TEE API for eps */
/* CRYPTO_TA_CHANNEL used in future release */
#define SW_EPS_CDRM 0x9140
#define SW_CRYPTO_CHAN_CDRM    SW_EPS_CDRM
#define SW_CRYPTO_ENHANCE_CDRM SW_EPS_CDRM

/* antiroot-eima2.0 */
/* eima */
#define SW_SYSCALL_NSHASHER_START          0xe403
#define SW_SYSCALL_NSHASHER_FINISH         0xe404
#define SW_SYSCALL_NSHASHER_UPDATE_FROM_NS 0xe405

/* privacy protection 0xe020-0xe03f */
#define SW_PRIP_POWERON          0xe020
#define SW_PRIP_POWEROFF         0xe021
#define SW_PRIP_RNG_GEN_TRND     0xe022
#define SW_PRIP_SM2_GEN_KEY      0xe023
#define SW_PRIP_SM2_ENCRYPT      0xe024
#define SW_PRIP_SM2_DECRYPT      0xe025
#define SW_PRIP_SM3_HASH_INIT    0xe026
#define SW_PRIP_SM3_HASH_UPDATE  0xe027
#define SW_PRIP_SM3_HASH_DOFINAL 0xe028
#define SW_PRIP_SM3_HASH_SIGLE   0xe029
#define SW_PRIP_SM4_SET_KEY      0xe02a
#define SW_PRIP_SM4_SET_IV       0xe02b
#define SW_PRIP_SM4_INIT         0xe02c
#define SW_PRIP_SM4_UDATE        0xe02d
#define SW_PRIP_SM4_DOFINAL      0xe02e
#define SW_PRIP_KM_DERIVE_KDR    0xe02f
#define SW_PRIP_SM9_SIGN         0xe030
#define SW_PRIP_SM9_VERIFY       0xe031
#define SW_PRIP_SM9_ENCRYPT      0xe032
#define SW_PRIP_SM9_DECRYPT      0xe033
#define SW_PRIP_SM9_WRAP_KEY     0xe034
#define SW_PRIP_SM9_UNWRAP_KEY   0xe035
#define SW_PRIP_SM9_PRE_DATA     0xe036


/* eiius(Encrypted Image Incremental Update Service)
 * It is close with secboot, so the id is similar with it's.
 */
#define SW_EIIUS_INCR_UPDATE   0xe010
#define SW_EIIUS_ENCRYPTO_DATA 0xe011
#define SW_EIIUS_MAP_ADDR      0xe012
#define SW_EIIUS_UNMAP_ADDR    0xe013
#define SW_EIIUS_COMPRESS_DATA 0xe014
#define SW_EIIUS_VERIFY_DATA   0xe015
#define SW_EIIUS_GET_PADDR     0xe016

/* hsm scmi */
#define SYSCALL_SCMI_CHANNEL_OPEN                   0xac01
#define SYSCALL_SCMI_CHANNEL_CLOSE                  0xac02
#define SYSCALL_SCMI_CHANNEL_SEND_DATA              0xac03
#define SYSCALL_SCMI_CHANNEL_TASK_AND_GET_DATA      0xac04
#define SYSCALL_SCMI_CHANNEL_PADDR2VADDR            0xac05

#define SYSCALL_SFC_FLASH_READ                      0xac07
#define SYSCALL_SFC_FLASH_WRITE                     0xac08
#define SYSCALL_SFC_FLASH_ERASE                     0xac09
#define SYSCALL_SFC_FLASH_PA2TAVA                   0xac0a

/* hsm secure update */
#define SYSCALL_SECURE_FLASH_READ                   0xac0b
#define SYSCALL_SECURE_FLASH_WRITE                  0xac0c
#define SYSCALL_SECURE_FLASH_ERASE                  0xac0d
#define SYSCALL_SECURE_IMG_VERIFY                   0xac0e
#define SYSCALL_SECURE_IMG_UPDATE                   0xac0f
#define SYSCALL_SECURE_UPDATE_FINISH                0xac10
#define SYSCALL_SECURE_VERSION_GET                  0xac11
#define SYSCALL_SECURE_COUNT_GET                    0xac12
#define SYSCALL_SECURE_INFO_GET                     0xac13
#define SYSCALL_SECURE_UFS_CNT_READ                 0xac14
#define SYSCALL_SECURE_UFS_CNT_WRITE                0xac15
#define SYSCALL_SECURE_VERIFY_STATUS_UPDATE         0xac16
#define SYSCALL_SECURE_IMG_SYNC                     0xac17
#define SYSCALL_UPGRADE_SRAM_READ                   0xac18
#define SYSCALL_UPGRADE_FLASH_READ                  0xac19
#define SYSCALL_UPGRADE_FLASH_WRITE                 0xac1a
#define SYSCALL_UPGRADE_RESET_CNT_READ              0xac1b
#define SYSCALL_UPGRADE_RESET_CNT_WRITE             0xac1c
#define SYSCALL_SECURE_ROOTKEY_GET                  0xac1d
#define SYSCALL_SECURE_CMDLINE_GET                  0xac1e
#define SYSCALL_REFLASH_HILINK                      0xac1f
#define SYSCALL_SECURE_PART_READ                    0xac20
#define SYSCALL_SECURE_GET_BLFLAG                   0xac21
#define SYSCALL_SECURE_SET_BLFLAG                   0xac22
#define SYSCALL_SECURE_HBOOT_TRANS                  0xac23
#define SYSCALL_SECURE_UPDATE_STATUS                0xac24
#define SYSCALL_GET_EFUSE_NVCNT                     0xac25
#define SYSCALL_GET_SYNC_FLAG                       0xac26
#define SYSCALL_GET_DEV_NUM                         0xac27
#define SYSCALL_SECURE_RECOVERY_CNT_WRITE           0xac28
/* hsm efuse */
#define SYSCALL_HSM_EFUSE_WRITE                     0xad01
#define SYSCALL_HSM_EFUSE_BURN                      0xad02
#define SYSCALL_HSM_EFUSE_CHECK                     0xad03
#define SYSCALL_HSM_EFUSE_NV_CNT_BURN               0xad04
#define SYSCALL_HSM_EFUSE_NV_CNT_CHECK              0xad05
#define SYSCALL_HSM_EFUSE_NS_FORIBID_CHECK          0xad06

/* hsm pg info get */
#define SYSCALL_HSM_PG_GET                          0xae01

/* low speed bus for test */
#ifdef DEF_ENG
#define SW_SYSCALL_LSBUS_DRV                        0xaf01
#endif

/* hsm mdc flash read */
#define SYSCALL_MDC_FLASH_READ                      0xaf0b
#define SYSCALL_MDC_FLASH_WRITE                     0xaf0c
#define SYSCALL_MDC_FLASH_ERASE                     0xaf0d
#endif /* __SRE_SYSCASLLS_ID_EXT_H__ */
