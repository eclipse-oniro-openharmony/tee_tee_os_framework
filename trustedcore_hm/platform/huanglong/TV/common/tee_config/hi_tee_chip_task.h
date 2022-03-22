/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: TA UUID and name
 * Create: 2017-06-17
 */

#ifndef __HI_TEE_CHIP_TASK_H
#define __HI_TEE_CHIP_TASK_H

/*
 * TA name
 */
#define HISI_DEMO_TASK_NAME         "task_hisi_demo"
#define HISI_SSM_TASK_NAME          "task_hisi_ssm"
#define HISI_SSM_TEST_TASK_NAME     "task_hisi_ssm_test"
#define HISI_SSM_TEST_2_TASK_NAME   "task_hisi_ssm_test_2"
#define HISI_DMX_TASK_NAME          "task_hisi_dmx"
#define HISI_PVR_TASK_NAME          "task_hisi_pvr"
#define HISI_TEST_CIPHER_TASK_NAME  "task_hisi_test_cipher"
#define HISI_KLAD_TASK_NAME         "task_hisi_klad"
#define HISI_OTP_TASK_NAME          "task_hisi_otp"
#define HISI_KEYSLOT_TASK_NAME      "task_hisi_keyslot"
#define HISI_VFMW_TASK_NAME         "task_hisi_vfmw"
#define HISI_SMMU_TASK_NAME         "smmu_task"
#define HISI_COMMON_TASK_NAME       "task_hisi_common"
#define HISI_HDMITX_TASK_NAME       "task_hisi_hdmitx"
#define HISI_HDMIRX_TASK_NAME       "task_hisi_hdmirx"
#define HISI_NPU_TEST_TASK_NAME     "task_hisi_npu_test"
#define CDRMKEY_TASK_NAME           "task_cdrm_key"

/*
 * TA UUID
 */
#define TEE_SERVICE_DEMO \
{ \
    0x8f194022, \
    0xc9a2, \
    0x11e6, \
    { \
        0x9d, 0x9d, 0xce, 0xc0, 0xc9, 0x32, 0xce, 0x01 \
    } \
}

#if defined(CFG_HI_TEE_WIDEVINE_SUPPORT)
/* widevine TA */
#define TEE_SERVICE_WIDEVINE \
{ \
    0x79b77788, \
    0x9789, \
    0x4a7a, \
    { \
        0xa2, 0xbe, 0xb6, 0x01, 0x55, 0xee, 0xf5, 0xf8 \
    } \
}
#endif

/**
 * @ingroup  TEE_ID
 *
 * WisePlay task
 */
#define TEE_SERVICE_WISEPLAY \
{ \
    0x3b4a2246, \
    0x96a1, \
    0x4697, \
    { \
        0xba, 0xdf, 0x72, 0xaf, 0x3d, 0xd2, 0x87, 0xe8 \
    } \
}

/* cdrm key TA */
#define TEE_SERVICE_CDRMKEY \
{ \
    0xa1da6d06, \
    0x43a0, \
    0x484f, \
    { \
        0x80, 0xb0, 0x4a, 0xfc, 0x5a, 0x8f, 0x0c, 0x4c \
    } \
}

#if defined(CFG_HI_TEE_EMPTYDRM_SUPPORT)
/* emptydrm TA */
#define TEE_SERVICE_EMPTYDRM \
{ \
    0x79b77788, \
    0x9789, \
    0x4a7a, \
    { \
        0xa2, 0xbe, 0xb6, 0x01, 0x55, 0x11, 0x11, 0x11 \
    } \
}
#endif

#if defined(CFG_HI_TEE_PLAYREADY_SUPPORT)
/* playready TA */
#define TEE_SERVICE_PLAYREADY \
{ \
    0x79b77788, \
    0x9789, \
    0x4a7a, \
    { \
        0xa2, 0xbe, 0xb6, 0x01, 0x55, 0xee, 0xf5, 0xf9 \
    } \
}
#endif

/* KeyMaster TA */
#define TEE_SERVICE_KEYMASTER_HISI \
{ \
    0x0bafcdc5, \
    0xe708, \
    0x5d7c, \
    { \
        0xa9, 0xbc, 0xe7, 0xde, 0x73, 0x3a, 0xc5, 0x28 \
    } \
}

/* Gatekeeper TA */
#define TEE_SERVICE_GATEKEEPER_HISI \
{ \
    0x8a15cfba, \
    0xd339, \
    0x474f, \
    { \
        0x86, 0xd1, 0xb3, 0xba, 0xe5, 0xd0, 0xf3, 0xff \
    } \
}

/* marlin TA */
#define TEE_SERVICE_MARLIN \
{ \
    0xed894d36, \
    0xff4b, \
    0x984f, \
    { \
        0xa9, 0x27, 0xb4, 0x15, 0x4f, 0x3f, 0x22, 0x51 \
    } \
}

/* NSTV DRM TA */
#define TEE_SERVICE_NSTV_DRM \
{ \
    0x866d6c6d, \
    0xdf3c, \
    0x4cfd, \
    { \
        0xb8, 0x92, 0x32, 0xd1, 0x76, 0x8d, 0xd0, 0x18 \
    } \
}


/* HDMI HDCP */
#define TEE_SERVICE_HDMITX \
{ \
    0x40e4a246, \
    0xc1a7, \
    0x11e6, \
    { \
        0xa4, 0xa6, 0xce, 0xc0, 0xc9, 0x32, 0xce, 0x01 \
    } \
}

/* CRYPTO_VERIFY */
#define TEE_SERVICE_CRYPTO_VERIFY \
{ \
    0x46b84766, \
    0x42b0, \
    0x11e6, \
    { \
        0xbe, 0xb8, 0x9e, 0x71, 0x12, 0x8c, 0xae, 0x77 \
    } \
}

#define TEE_SERVICE_DRM_HISI \
{ \
    0x14047d2d, \
    0xf236, \
    0x48a0, \
    { \
        0xa0, 0xc4, 0xc1, 0xcc, 0xcb, 0xb6, 0x45, 0x46 \
    } \
}

/* SEC_MMZ TA */
#define TEE_SERVICE_SEC_MMZ \
{ \
    0xd93d4688, \
    0xbde7, \
    0x11e6, \
    { \
        0xa4, 0xa6, 0xce, 0xc0, 0xc9, 0x32, 0xce, 0x01 \
    } \
}

/* VFMW TA */
#define TEE_SERVICE_VFMW \
{ \
    0x3c2bfc84, \
    0xc03c, \
    0x11e6, \
    { \
        0xa4, 0xa6, 0xce, 0xc0, 0xc9, 0x32, 0xce, 0x01 \
    } \
}

/* CIPHER TA */
#define TEE_SERVICE_CIPHER \
{\
    0x04ae2ac0, \
    0x01e8, \
    0x4587, \
    {\
        0xb3, 0xda, 0x38, 0xf5, 0x98, 0x46, 0xbc, 0x57 \
    }\
}

/* CIPHER_TEST */
#define TEE_SERVICE_HISI_CIPHER_TEST \
{ \
    0x0E0E0E0E, \
    0x0E0E, \
    0x0E0E, \
    { \
        0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E \
    } \
}

#define TEE_SERVICE_VDP_VMX_WATERMARK \
{ \
    0x1E1E1E1E, \
    0x1E1E, \
    0x1E1E, \
    { \
        0x1E, 0x1E, 0x1E, 0x1E, 0x1E, 0x1E, 0x1E, 0x1E \
    } \
}

#define TEE_SERVICE_VDP_NXG_WATERMARK \
{ \
    0x528f2387, \
    0x7a02, \
    0x483e, \
    { \
        0x9F, 0xD3, 0xFB, 0xCD, 0x9D, 0x17, 0x5B, 0xDC \
    } \
}

/*
 * NAGRA_CONNECT task
 * UUID: ea03fd02-80c4-41f6-a3e9-580e48a264cc
 */
#define TEE_SERVICE_NAGRA_CONNECT \
{ \
    0xea03fd02, \
    0x80c4, \
    0x41f6, \
    { \
        0xa3, 0xe9, 0x58, 0x0e, 0x48, 0xa2, 0x64, 0xcc \
    } \
}

/*
 * nexguard task
 * UUID: 528f2387-7a02-483e-9fd3-fbcd9d175bdc
 */
#define TEE_SERVICE_NEXGUARD \
{ \
    0x528f2387, \
    0x7a02, \
    0x483e, \
    { \
        0x9f, 0xd3, 0xfb, 0xcd, 0x9d, 0x17, 0x5b, 0xdc \
    } \
}

/*
 * irdeto task
 * UUID: c5cad123-203b-4924-8e4a-c5cc20959857
 */
#define TEE_SERVICE_IRDETO \
{ \
    0xc5cad123, \
    0x203b, \
    0x4924, \
    { \
        0x8e, 0x4a, 0xc5, 0xcc, 0x20, 0x95, 0x98, 0x57 \
    } \
}

/*
 * conax task
 * UUID: a0bcb0c2-8979-4423-8062-d1affe3ab22b
 */
#define TEE_SERVICE_CONAX \
{ \
    0xa0bcb0c2, \
    0x8979, \
    0x4423, \
    { \
        0x80, 0x62, 0xd1, 0xaf, 0xfe, 0x3a, 0xb2, 0x2b \
    } \
}

/* SMMU TASK */
#define TEE_SERVICE_SMMU \
{\
    0x08684bd8, \
    0xbde8, \
    0x11e6, \
    {\
        0xa4, 0xa6, 0xce, 0xc0, 0xc9, 0x32, 0xce, 0x01 \
    }\
}

#define TEE_SERVICE_VPSS \
{\
    0x3acc8b1b, \
    0xa7e1, \
    0xe511, \
    {\
        0xb8,0x6d,0x9a,0x79,0xf0,0x6e,0x94,0x78 \
    }\
}

/* DMX task */
#define TEE_SERVICE_DMX \
{\
    0xca0b4c78, \
    0xbcf2, \
    0x11e6, \
    {\
        0xa4, 0xa6, 0xce, 0xc0, 0xc9, 0x32, 0xce, 0x01 \
    }\
}

/* TSR2RCIPHER task */
#define TEE_SERVICE_TSR2RCIPHER \
{\
    0x7ce373d9, \
    0x60f7, \
    0x43aa, \
    {\
        0xa7, 0x3f, 0x4e, 0x6b, 0xc9, 0x85, 0x99, 0x6b \
    }\
}

/* CRYPTOEN task */
#define TEE_SERVICE_CRYPTOEN \
{\
    0xd9420c8e, \
    0x8daa, \
    0x439d, \
    {\
        0xa1, 0xe2, 0x91, 0x30, 0x16, 0xb1, 0x81, 0x0c \
    }\
}

/* PVR task */
#define TEE_SERVICE_PVR \
{\
    0x569985fe,\
    0xbac0,\
    0x11e6,\
    {\
        0xa4, 0xa6, 0xce, 0xc0, 0xc9, 0x32, 0xce, 0x01\
    }\
}

/* AVPLAY task */
#define TEE_SERVICE_AVPLAY \
{ \
    0x99985ef1, \
    0xd62d, \
    0x4524, \
    { \
        0x9d, 0xd1, 0xd9, 0x83, 0x45, 0x48, 0xd9, 0x8e \
    } \
}

/* LOG task */
#define TEE_SERVICE_LOG \
{ \
    0x99986666, \
    0x6666, \
    0x4566, \
    { \
        0x96, 0xd6, 0xd6, 0x86, 0x46, 0x46, 0xd6, 0x86 \
    } \
}

/* VMX ULTRA VMXTA task */
#define TEE_SERVICE_STB_VMX_ULTRA_VMXTA \
{ \
    0xd70f330c, \
    0xc8dd, \
    0x11e6, \
    { \
        0x9d, 0x9d, 0xce, 0xc0, 0xc9, 0x32, 0xce, 0x01 \
    } \
}

#define TEE_SERVICE_STB_VMX_ULTRA_DVB_TA TEE_SERVICE_STB_VMX_ULTRA_VMXTA
/* VMX ULTRA videomarkTA task */
#define TEE_SERVICE_STB_VMX_ULTRA_VIDOMARK_TA \
{ \
    0xd70f3550, \
    0xc8dd, \
    0x11e6, \
    { \
        0x9d, 0x9d, 0xce, 0xc0, 0xc9, 0x32, 0xce, 0x01 \
    } \
}

/* VMX ULTRA TEE_SERVICE_STB_VMX_ULTRA_OTT_TA */
#define TEE_SERVICE_STB_VMX_ULTRA_VMXTAC_TEST_TA2 \
{ \
    0xd70f364a, \
    0xc8dd, \
    0x11e6, \
    { \
        0x9d, 0x9d, 0xce, 0xc0, 0xc9, 0x32, 0xce, 0x01 \
    } \
}
#define TEE_SERVICE_STB_VMX_ULTRA_OTT_TA TEE_SERVICE_STB_VMX_ULTRA_VMXTAC_TEST_TA2

/* VMX ULTRA TEE_SERVICE_STB_VMX_ULTRA_RESERVED_TA */
#define TEE_SERVICE_STB_VMX_ULTRA_VMXTAC_TEST_TA3 \
{ \
    0xd70f3726, \
    0xc8dd, \
    0x11e6, \
    { \
        0x9d, 0x9d, 0xce, 0xc0, 0xc9, 0x32, 0xce, 0x01 \
    } \
}

#define TEE_SERVICE_STB_VMX_ULTRA_RESERVED_TA TEE_SERVICE_STB_VMX_ULTRA_VMXTAC_TEST_TA3

/* VMX ULTRA TEE_SERVICE_STB_VMX_ULTRA_IPTV_TA */
#define TEE_SERVICE_STB_VMX_ULTRA_VMXTAC_TEST_TA1 \
{ \
    0xd70f3a8c, \
    0xc8dd, \
    0x11e6, \
    { \
        0x9d, 0x9d, 0xce, 0xc0, 0xc9, 0x32, 0xce, 0x01 \
    } \
}

#define TEE_SERVICE_STB_VMX_ULTRA_IPTV_TA TEE_SERVICE_STB_VMX_ULTRA_VMXTAC_TEST_TA1

/* VMX ULTRA update TA */
#define TEE_SERVICE_STB_UPDATE_TA \
{ \
    0x66666666, \
    0x6666, \
    0x6666, \
    { \
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 \
    } \
}

/* VMX ULTRA diplay TA */
#define TEE_SERVICE_STB_DISPLAY_TA \
{ \
    0x77777777, \
    0x7777, \
    0x7777, \
    { \
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77 \
    } \
}


/*
 * DCAS_COMMON task
 * UUID: 9546a217-c9e0-40df-b8b2-e161e102e585
 */
#define TEE_SERVICE_DCAS_COMMON \
{ \
    0x17a24695, \
    0xe0c9, \
    0xdf40, \
    { \
        0xb8, 0xb2, 0xe1, 0x61, 0xe1, 0x02, 0xe5, 0x85 \
    } \
}

/*
 * DCAS_NDS task
 * UUID: 2e8021e9-af35-4599-95baf374c229adb3
 */
#define TEE_SERVICE_DCAS_NDS \
{ \
    0xe921802e, \
    0x35af, \
    0x9945, \
    { \
        0x95, 0xba, 0xf3, 0x74, 0xc2, 0x29, 0xad, 0xb3 \
    } \
}

/*
 * sumavision TA task
 * UUID: 3ddb56c2-0f03-4888-ae19-eca62e59917e
 */
#define TEE_SERVICE_DCAS_SUMA \
{ \
    0xc256db3d, \
    0x030f, \
    0x8848, \
    { \
        0xae, 0x19, 0xec, 0xa6, 0x2e, 0x59, 0x91, 0x7e \
    } \
}

/*
 * novel-superTV TA task
 * UUID: 888105c8-4d8a-704b-891e1631f8b8f388
 */
#define TEE_SERVICE_DCAS_NOVEL \
{ \
    0xc8058188, \
    0x8a4d, \
    0x4b70, \
    { \
        0x89, 0x1e, 0x16, 0x31, 0xf8, 0xb8, 0xf3, 0x88 \
    } \
}

/* NETFLIX TA */
#define TEE_SERVICE_NETFLIX \
{ \
    0x4c526126, \
    0xa26f, \
    0x452f, \
    { \
        0xb4, 0x8f, 0x37, 0x4c, 0x09, 0x38, 0x62, 0x31 \
    } \
}

/* SUMA TA */
#define TEE_SERVICE_SUMA \
{ \
    0xdb057c3e, \
    0x0eae, \
    0x11e7, \
    { \
        0x93, 0xae, 0x92, 0x36, 0x1f, 0x00, 0x26, 0x71 \
    } \
}

/* session manage TA */
#define TEE_SERVICE_SSM \
{ \
    0x90ae48e5, \
    0xc757, \
    0x44a7, \
    { \
        0xb5, 0x13, 0xde, 0x4b, 0x2b, 0x14, 0xa0, 0x7c \
    } \
}

#define TEE_SERVICE_SSM_TEST \
{ \
    0xfcb56fcc, \
    0xd852, \
    0x11e9, \
    { \
        0x8a, 0x34, 0x2a, 0x2a, 0xe2, 0xdb, 0xcc, 0xe4 \
    } \
}

#define TEE_SERVICE_SSM_TEST_2 \
{ \
    0xb07f6107, \
    0xcd11, \
    0x4ae1, \
    { \
        0xba, 0xf4, 0xfe, 0x70, 0xab, 0x65, 0xb4, 0x1c \
    } \
}

/* KLAD TA */
#define TEE_SERVICE_KLAD \
{\
    0xc9cf6b2a, \
    0x4b60, \
    0x11e7, \
    {\
        0xa9, 0x19, 0x92, 0xeb, 0xcb, 0x67, 0xfe, 0x33 \
    }\
}

/* OTP TA */
#define TEE_SERVICE_OTP \
{\
    0x7ece101c, \
    0xe197, \
    0x11e8, \
    {\
        0x9f, 0x32, 0xf2, 0x80, 0x1f, 0x1b, 0x9f, 0xd1 \
    }\
}

/* COMMON TA */
#define TEE_SERVICE_COMMON \
{\
    0x000ac3b0, \
    0xbf6f, \
    0x11e7, \
    {\
        0x8f, 0x1a, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66 \
    }\
}

/* UNITEND UDRM TA */
#define TEE_SERVICE_UNITEND_UDRM \
{\
    0xaa11967f, \
    0xcc01, \
    0x4a4a, \
    {\
        0x8e, 0x99, 0xc5, 0xd3, 0xdd, 0xdf, 0xea, 0x2d \
    }\
}

/*
 * TELECOM TM TA
 */
#define TEE_SERVICE_TELECOM_TM \
{\
    0x7ebece2e, \
    0xa517, \
    0x4e10, \
    {\
        0x89, 0x2f, 0xd2, 0x28, 0x39, 0xc7, 0x20, 0xed \
    }\
}

/*
 * IRDETO DRM TA
 */
#define TEE_SERVICE_IRDETO_DRM \
{\
    0x4368696e, \
    0x6144, \
    0x524d, \
    {\
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 \
    }\
}

/*
 * IRDETO TM TA
 */
#define TEE_SERVICE_IRDETO_TM \
{\
    0x12345678, \
    0x8765, \
    0x4321, \
    {\
        0x63, 0x74, 0x63, 0x74, 0x6d, 0x74, 0x61, 0x20 \
    }\
}

/*
 * OPENTV5 task
 * UUID: a22d3496-6678-4560-a8ec-884871a16260
 */
#define TEE_SERVICE_OPENTV5 \
{ \
    0xa22d3496, \
    0x6678, \
    0x4560, \
    { \
        0xa8, 0xec, 0x88, 0x48, 0x71, 0xa1, 0x62, 0x60 \
    } \
}

/*
 * SCI TA task
 * UUID: f2898a06-649b-4e47-b946-858516377ea6
 */
#define TEE_SERVICE_SCI \
{ \
    0x068A89F2, \
    0x9b64, \
    0x474e, \
    { \
        0xb9, 0x46, 0x85, 0x85, 0x16, 0x37, 0x7e, 0xa6 \
    } \
}

/* HISI_TEST_CIPHER task */
#define TEE_SERVICE_TEST_CIPHER                            \
    {                                                      \
        0x00000000,                                        \
            0x0000,                                        \
            0x0000,                                        \
        {                                                  \
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 \
        }                                                  \
    }

/*
 * KEYSLOT TA task
 * UUID: 59e80d08-ad42-11e9-a2a3-2a2ae2dbcce4
 */
#define TEE_SERVICE_KEYSLOT \
{ \
    0x59e80d08, \
    0xad42, \
    0x11e9, \
    { \
        0xa2, 0xa3, 0x2a, 0x2a, 0xe2, 0xdb, 0xcc, 0xe4 \
    } \
}

/*
 * HDMIRX TA task
 * UUID: 28d83cf8-186e-51ec-be8d-12201b76f71e
 */
#define TEE_SERVICE_HDMIRX \
{ \
    0x28d83cf8, \
    0x186e, \
    0x51ec, \
    { \
        0xbe, 0x8d, 0x12, 0x20, 0x1b, 0x76, 0xf7, 0x1e \
    } \
}

/*
 * NPU TA test task
 * UUID: fbc65cfc-8d25-9e11-348a-e42adbe2cc2a
 */
#define TEE_SERVICE_NPU_TEST \
{ \
    0xfbc65cfc, \
    0x8d25, \
    0x9e11, \
    { \
        0x34, 0x8a, 0xe4, 0x2a, 0xdb, 0xe2, 0xcc, 0x2a \
    } \
}

/*
 * NPU TA dynion
 * UUID: 2e30c761-3d84-4544-af23-aecd2eb08d08
 */
#define TEE_SERVICE_NPU_DRV \
{ \
    0x2e30c761, \
    0x3d84, \
    0x4544, \
    { \
        0xaf, 0x23, 0xae, 0xcd, 0x2e, 0xb0, 0x8d, 0x08 \
    } \
}

#endif  /* __HI_TEE_CHIP_TASK_H */
