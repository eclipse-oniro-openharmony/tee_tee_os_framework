/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: product uuid public declare
 * Create: 2021-1-1
 */
#ifndef PLATFORM_PRODUCT_UUID_PUBLIC_H
#define PLATFORM_PRODUCT_UUID_PUBLIC_H

#include "tee_test_uuid.h"

/* dca5ae8a-769e-4e24-896b-7d06442c1c0e */
#define TEE_SERVICE_SECISP                                 \
    {                                                      \
        0xDCA5AE8A, 0x769E, 0x4E24,                        \
        {                                                  \
            0x89, 0x6B, 0x7D, 0x06, 0x44, 0x2C, 0x1C, 0x0E \
        }                                                  \
    }

#define TEE_DF_AC_SERVICE                                  \
    {                                                      \
        0xd77c4d60, 0xd279, 0x4425,                        \
        {                                                  \
            0xaf, 0xa8, 0x7f, 0x94, 0x55, 0x9e, 0xae, 0x16 \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * CCB TA
 * 33dea9bd-f02f-42f2-bc3e-1280abf6eece
 */
#define TEE_SERVICE_CCB                                    \
    {                                                      \
        0x33dea9bd, 0xf02f, 0x42f2,                        \
        {                                                  \
            0xbc, 0x3e, 0x12, 0x80, 0xab, 0xf6, 0xee, 0xce \
        }                                                  \
    }
/* b0b71695-2913-4fc1-8e7f-427d92212247 */
#define TEE_SERVICE_BDKERNEL                               \
    {                                                      \
        0xb0b71695, 0x2913, 0x4fc1,                        \
        {                                                  \
            0x8e, 0x7f, 0x42, 0x7d, 0x92, 0x21, 0x22, 0x47 \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * CFCA TA
 * f85146a0-9691-450f-ae9d-41c811515c5e
 */
#define TEE_SERVICE_CFCA                                   \
    {                                                      \
        0xf85146a0, 0x9691, 0x450f,                        \
        {                                                  \
            0xae, 0x9d, 0x41, 0xc8, 0x11, 0x51, 0x5c, 0x5e \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * Used: Nanjing Bank TA, vendor: YangFanWeiYe, 2017.12.15
 *
 * 0686889d-2338-4858-92cc-70913d31a23a
 */
#define TEE_SERVICE_BAK                                    \
    {                                                      \
        0x0686889d, 0x2338, 0x4858,                        \
        {                                                  \
            0x92, 0xcc, 0x70, 0x91, 0x3d, 0x31, 0xa2, 0x3a \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * FingerPrint TA
 * a32b3d00-cb57-11e3-9c1a-0800200c9a66.sec
 */
#define TEE_SERVICE_FINGERPRINT                            \
    {                                                      \
        0xa32b3d00, 0xcb57, 0x11e3,                        \
        {                                                  \
            0x9c, 0x1a, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66 \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * FingerPrint Coating check TA
 * e5c6a727-c219-aa13-3e14-444d853a200a.sec
 */
#define TEE_FINGERPRINT_COATING_CHECK                      \
    {                                                      \
        0xe5c6a727, 0xc219, 0xaa13,                        \
        {                                                  \
            0x3e, 0x14, 0x44, 0x4d, 0x85, 0x3a, 0x20, 0x0a \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * FingerPrint Sensor check TA
 * use this TA to check the fp senor:fpc or other vendor
 * fd1bbfb2-9a62-4b27-8fdb-a503529076af.sec
 */
#define TEE_FINGERPRINT_SENSOR_CHECK                       \
    {                                                      \
        0xfd1bbfb2, 0x9a62, 0x4b27,                        \
        {                                                  \
            0x8f, 0xdb, 0xa5, 0x03, 0x52, 0x90, 0x76, 0xaf \
        }                                                  \
    }
/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * SignTool TA:used to store huawei VIP key
 * 9b17660b-8968-4eed-917e-dd32379bd548
 */
#define TEE_SERVICE_SIGNTOOL                               \
    {                                                      \
        0x9b17660b, 0x8968, 0x4eed,                        \
        {                                                  \
            0x91, 0x7e, 0xdd, 0x32, 0x37, 0x9b, 0xd5, 0x48 \
        }                                                  \
    }
/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * product line RPMB key write TA
 * 6c8cf255-ca98-439e-a98e-ade64022ecb6
 */
#define TEE_SERVICE_RPMBKEY                                \
    {                                                      \
        0x6c8cf255, 0xca98, 0x439e,                        \
        {                                                  \
            0xa9, 0x8e, 0xad, 0xe6, 0x40, 0x22, 0xec, 0xb6 \
        }                                                  \
    }
/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * product line spi bus check
 * 868ccafb-794b-46c6-b5c4-9f1462de4e02
 */
#define TEE_SERVICE_HARDWARECHECK                          \
    {                                                      \
        0x868ccafb, 0x794b, 0x46c6,                        \
        {                                                  \
            0xb5, 0xc4, 0x9f, 0x14, 0x62, 0xde, 0x4e, 0x02 \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * Huawei wallet TA:used to check spi in product line
 * 4ae7ba51-2810-4cee-abbe-a42307b4ace3
 */
#define TEE_SERVICE_WALLET                           \
    {                                                      \
        0x4ae7ba51, 0x2810, 0x4cee,                        \
        {                                                  \
            0xab, 0xbe, 0xa4, 0x23, 0x07, 0xb4, 0xac, 0xe3 \
        }                                                  \
    }
/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * SKYTONE TA
 * abe89147-cd61-f43f-71c4-1a317e405312.sec
 */
#define TEE_SERVICE_SKYTONE                                \
    {                                                      \
        0xabe89147, 0xcd61, 0xf43f,                        \
        {                                                  \
            0x71, 0xc4, 0x1a, 0x31, 0x7e, 0x40, 0x53, 0x12 \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * SKYTONE TA
 * 3a8bddbc-7151-11e5-9d70-feff819cdc9f.sec
 */
#define TEE_SERVICE_SKYTONE_UI                             \
    {                                                      \
        0x3a8bddbc, 0x7151, 0x11e5,                        \
        {                                                  \
            0x9d, 0x70, 0xfe, 0xff, 0x81, 0x9c, 0xdc, 0x9f \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * crypto sms TA:used to encrypt sms in carrara
 * 79b77788-9789-4a7a-a2be-b60155eef5f4
 */
#define TEE_SERVICE_CRYPTOSMS                              \
    {                                                      \
        0x79b77788, 0x9789, 0x4a7a,                        \
        {                                                  \
            0xa2, 0xbe, 0xb6, 0x01, 0x55, 0xee, 0xf5, 0xf4 \
        }                                                  \
    }
/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * alipay TA from zhifubao:used for zhifubao
 * 66302DF4-31F2-1782-042F-A55C7466DA21
 */
#define TEE_SERVICE_ALIPAY                                 \
    {                                                      \
        0x66302DF4, 0x31F2, 0x1782,                        \
        {                                                  \
            0x04, 0x2F, 0xA5, 0x5C, 0x74, 0x66, 0xDA, 0x21 \
        }                                                  \
    }
/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * wechat TA from tencent:used for wechar pay
 * B7C9A7FD-851E-7761-07DF-8AB7C0B02787
 */
#define TEE_SERVICE_WECHAT                                 \
    {                                                      \
        0xB7C9A7FD, 0x851E, 0x7761,                        \
        {                                                  \
            0x07, 0xdf, 0x8a, 0xb7, 0xc0, 0xb0, 0x27, 0x87 \
        }                                                  \
    }
/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * antitheft TA from huawei:used for device antitheft
 * b4b71581-add2-e89f-d536-f35436dc7973
 */
#define TEE_SERVICE_ANTITHEFT                              \
    {                                                      \
        0xB4B71581, 0xADD2, 0xE89F,                        \
        {                                                  \
            0xD5, 0x36, 0xF3, 0x54, 0x36, 0xDC, 0x79, 0x73 \
        }                                                  \
    }
/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * widevine TA
 * a3d05777-b0ec-43b0-8887-a7f93697830a a3d05777-b0ec-43b0-8887-a7f93697830a.sec
 */
#define TEE_SERVICE_WIDEVINE_DRM                           \
    {                                                      \
        0xA3D05777, 0xB0EC, 0x43B0,                        \
        {                                                  \
            0x88, 0x87, 0xA7, 0xF9, 0x36, 0x97, 0x83, 0x0A \
        }                                                  \
    }
/* @ingroup  TEE_CONFIG_DATA
 *
 * FIDO TA from huawei
 * 883890ba-3ef8-4f0b-9c02-f5874acbf2ff
 */
#define TEE_SERVICE_FIDO                                   \
    {                                                      \
        0x883890ba, 0x3ef8, 0x4f0b,                        \
        {                                                  \
            0x9c, 0x02, 0xf5, 0x87, 0x4a, 0xcb, 0xf2, 0xff \
        }                                                  \
    }

/* @ingroup  TEE_CONFIG_IFAA
 *
 * IFAA TA from huawei
 * 993e26b8-0273-408e-98d3-60c997c37121
 */
#define TEE_SERVICE_IFAA                                   \
    {                                                      \
        0x993e26b8, 0x0273, 0x408e,                        \
        {                                                  \
            0x98, 0xd3, 0x60, 0xc9, 0x97, 0xc3, 0x71, 0x21 \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * sensor info TA from huawei to check fingerprint sensor type
 * fd1bbfb2-9a62-4b27-8fdb-a503529076af
 */
#define TEE_SERVICE_SENSORINFO                             \
    {                                                      \
        0xfd1bbfb2, 0x9a62, 0x4b27,                        \
        {                                                  \
            0x8f, 0xdb, 0xa5, 0x03, 0x52, 0x90, 0x76, 0xaf \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * under screen fingerpeint TA from huawei
 * a423e43d-abfd-441f-b89d-39e39f3d7f65
 */
#define TEE_SERVICE_UDFINGERPRINT                          \
    {                                                      \
        0xa423e43d, 0xabfd, 0x441f,                        \
        {                                                  \
            0xb8, 0x9d, 0x39, 0xe3, 0x9f, 0x3d, 0x7f, 0x65 \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * mmz ta
 * 814e69b9-7646-4467-a94c-6b136c16b5fb
 */
#define TEE_SERVICE_MMZ                                    \
    {                                                      \
        0x814e69b9, 0x7646, 0x4467,                        \
        {                                                  \
            0xa9, 0x4c, 0x6b, 0x13, 0x6c, 0x16, 0xb5, 0xfb \
        }                                                  \
    }

/*
 * @ingroup  TEE_SERVICE_IRIS
 *
 * iris ta
 * d28e1250-d4df-496d-9fcc-2181c3a2f4fa
 */
#define TEE_SERVICE_IRIS                                   \
    {                                                      \
        0xd28e1250, 0xd4df, 0x496d,                        \
        {                                                  \
            0x9f, 0xcc, 0x21, 0x81, 0xc3, 0xa2, 0xf4, 0xfa \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * playready TA
 * 3aff22b9-08d1-470c-9f47-c40494c6dfd9
 */
#define TEE_SERVICE_PLAYREADY_DRM                           \
    {                                                       \
        0xfffd3e45, 0xed54, 0x48ae,                         \
        {                                                   \
            0xb5, 0x7c, 0x44, 0x92, 0x5b, 0x86, 0x70, 0xc0  \
        }                                                   \
    }

/*
 * @ingroup  TEE_SERVICE_DTV
 *
 * DTV TA
 * a5b7a277-cd26-fd73-d847-e4a9f88b5310
 */
#define TEE_SERVICE_DTV                                    \
    {                                                      \
        0xa5b7a277, 0xcd26, 0xfd73,                        \
        {                                                  \
            0xd8, 0x47, 0xe4, 0xa9, 0xf8, 0x8b, 0x53, 0x10 \
        }                                                  \
    }

#define TEE_SERVICE_THPTUI                                 \
    {                                                      \
        0xe2983b4f, 0x1683, 0x4445,                        \
        {                                                  \
            0x9e, 0xec, 0x1f, 0x73, 0x18, 0x75, 0x77, 0x92 \
        }                                                  \
    }

/*
fingerprint Beta save crpto image
*/
#define TEE_SERVICE_FINGERPRINT_SAVEIMAGE                  \
    {                                                      \
        0xedbae857, 0xddb2, 0x484a,                        \
        {                                                  \
            0x83, 0xf2, 0xe1, 0xad, 0x2b, 0xeb, 0x56, 0xb2 \
        }                                                  \
    }

#define TEE_SERVICE_PKI                                    \
    {                                                      \
        0x86310d18, 0x5659, 0x47c9,                        \
        {                                                  \
            0xb2, 0x12, 0x84, 0x1a, 0x3c, 0xa4, 0xf8, 0x14 \
        }                                                  \
    }
/*
 * @ingroup  TEE_SERVICE_FACE_REC
 *
 * Face Recognition TA
 * e8014913-e501-4d44-a9d6-058ec3b93b90
 */
#define TEE_SERVICE_FACE_REC                               \
    {                                                      \
        0xe8014913, 0xe501, 0x4d44,                        \
        {                                                  \
            0xa9, 0xd6, 0x05, 0x8e, 0xc3, 0xb9, 0x3b, 0x90 \
        }                                                  \
    }

/* 859703f3-3cc5-4e88-b263-08f9ce82e3d0 */
#define TEE_SERVICE_VOICE_REC                              \
    {                                                      \
        0x859703f3, 0x3cc5, 0x4e88,                        \
        {                                                  \
            0xb2, 0x63, 0x08, 0xf9, 0xce, 0x82, 0xe3, 0xd0 \
        }                                                  \
    }

#define TEE_SERVICE_EID_U3                                 \
    {                                                      \
        0x335129cd, 0x41fa, 0x4b53,                        \
        {                                                  \
            0x97, 0x97, 0x5c, 0xcb, 0x20, 0x2a, 0x52, 0xd4 \
        }                                                  \
    }
#define TEE_SERVICE_EID_U1                                 \
    {                                                      \
        0x8780dda1, 0xa49e, 0x45f4,                        \
        {                                                  \
            0x96, 0x97, 0xc7, 0xed, 0x9e, 0x38, 0x5e, 0x83 \
        }                                                  \
    }
#define TEE_SERVICE_WEAVER                                 \
    {                                                      \
        0x42abc5f0, 0x2d2e, 0x4c3d,                        \
        {                                                  \
            0x8c, 0x3f, 0x34, 0x99, 0x78, 0x3c, 0xa9, 0x73 \
        }                                                  \
    }
/*
 * BYOD TA
 * e00d7df7-79e5-4507-9d8c-df03d5a7a8a5
 */
#define TEE_SERVICE_BYOD                                   \
    {                                                      \
        0xe00d7df7, 0x79e5, 0x4507,                        \
        {                                                  \
            0x9d, 0x8c, 0xdf, 0x03, 0xd5, 0xa7, 0xa8, 0xa5 \
        }                                                  \
    }

/*
 * CHINADRM TA
 * 866d6c6d-df3c-4cfd-b892-32d1768dd018
 */
#define TEE_SERVICE_CHINADRM                               \
    {                                                      \
        0x866d6c6d, 0xdf3c, 0x4cfd,                        \
        {                                                  \
            0xb8, 0x92, 0x32, 0xd1, 0x76, 0x8d, 0xd0, 0x18 \
        }                                                  \
    }

#define TEE_CHINADRM_2                                     \
    {                                                      \
        0x95b9ad1e, 0x0af8, 0x4201,                        \
        {                                                  \
            0x98, 0x91, 0x0d, 0xbe, 0x86, 0x02, 0xf3, 0x5f \
        }                                                  \
    }

#define TEE_CHANNEL_IPK                                    \
    {                                                      \
        0x70474f43, 0x0343, 0x4bb9,                        \
        {                                                  \
            0xa4, 0x97, 0x54, 0x26, 0xf6, 0xf1, 0x8d, 0x9f \
        }                                                  \
    }

/* 54ad737b-d84a-46bd-b993-1a90883f66f7 */
#define TEE_SERVICE_PANPAY                                 \
    {                                                      \
        0x54ad737b, 0xd84a, 0x46bd,                        \
        {                                                  \
            0xb9, 0x93, 0x1a, 0x90, 0x88, 0x3f, 0x66, 0xf7 \
        }                                                  \
    }

/* 57932c27-27c7-4e9b-a7c8-c3e9c6aba3d5 */
#define TEE_SERVICE_EIIUS                                  \
    {                                                      \
        0x57932c27, 0x27c7, 0x4e9b,                        \
        {                                                  \
            0xa7, 0xc8, 0xc3, 0xe9, 0xc6, 0xab, 0xa3, 0xd5 \
        }                                                  \
    }

/* 19909dea-b0d3-415c-8bc8-6e0773b8ab56 */
#define TEE_SERVICE_EPS                                  \
    {                                                      \
        0x19909dea, 0xb0d3, 0x415c,                        \
        {                                                  \
            0x8b, 0xc8, 0x6e, 0x07, 0x73, 0xb8, 0xab, 0x56 \
        }                                                  \
    }

/* 1ebffff1-d04a-4739-9f28-3a22161e9a34I */
#define TEE_SERVICE_PRIP                                   \
    {                                                      \
        0x1ebffff1, 0xd04a, 0x4739,                        \
        {                                                  \
            0x9f, 0x28, 0x3a, 0x22, 0x16, 0x1e, 0x9a, 0x34 \
        }                                                  \
    }

/* 5700f837-8b8e-4661-800b-42bb3fc3141f */
#define TEE_SERVICE_DRM_GRALLOC                            \
    {                                                      \
        0x5700f837, 0x8b8e, 0x4661,                        \
        {                                                  \
            0x80, 0x0b, 0x42, 0xbb, 0x3f, 0xc3, 0x14, 0x1f \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 * secboot service
 */
#define TEE_SERVICE_SECBOOT                                \
    {                                                      \
        0x08080808, 0x0808, 0x0808,                        \
        {                                                  \
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08 \
        }                                                  \
    }


#define TEE_SERVICE_DEMO                              \
    {                                                      \
        0x8f194022, 0xc9a2, 0x11e6,                        \
        {                                                  \
            0x9d, 0x9d, 0xce, 0xc0, 0xc9, 0x32, 0xce, 0x01 \
        }                                                  \
    }

/* 859703f3-3cc5-4e88-b263-08f9ce82e3d0 */
#define TEE_SERVICE_VOICE_REC                              \
    {                                                      \
        0x859703f3, 0x3cc5, 0x4e88,                        \
        {                                                  \
            0xb2, 0x63, 0x08, 0xf9, 0xce, 0x82, 0xe3, 0xd0 \
        }                                                  \
    }

#define TEE_SERVICE_VDEC                                   \
    {                                                      \
        0x4A1A44E8, 0x3ED7, 0x4E00,                        \
        {                                                  \
            0x9C, 0x1E, 0x02, 0xA2, 0x57, 0x7E, 0xA2, 0x4A \
        }                                                  \
    }

/* e7ed1f64-4687-41da-96dc-cbe4f27c838f */
#define TEE_SERVICE_ANTIROOT                               \
    {                                                      \
        0xE7ED1F64, 0x4687, 0x41DA,                        \
        {                                                  \
            0x96, 0xDC, 0xCB, 0xE4, 0xF2, 0x7C, 0x83, 0x8F \
        }                                                  \
    }

/*
 * @ingroup  TEE_HI_VCODEC
 * hivcodec
 * 528822b7-fc78-466b-b57e-62093d6034a7
 */
#define TEE_SERVICE_HIVCODEC                               \
    {                                                      \
        0x528822b7, 0xfc78, 0x466b,                        \
        {                                                  \
            0xb5, 0x7e, 0x62, 0x09, 0x3d, 0x60, 0x34, 0xa7 \
        }                                                  \
    }

/*
 * @ingroup  TEE_HI_VCODEC
 * hivcodec_sr
 * f92dbe38-4d09-4422-aa34-14992e2a0bf2
 */
#define TEE_SERVICE_HIVCODEC_SR                            \
    {                                                      \
        0xf92dbe38, 0x4d09, 0x4422,                        \
        {                                                  \
            0xaa, 0x34, 0x14, 0x99, 0x2e, 0x2a, 0x0b, 0xf2 \
        }                                                  \
    }


#define TEE_SERVICE_AI                                     \
    {                                                      \
        0xf4a8816d, 0xb6fb, 0x4d4f,                        \
        {                                                  \
            0xa2, 0xb9, 0x7d, 0xae, 0x57, 0x33, 0x13, 0xc0 \
        }                                                  \
    }

/* 54ff868f-0d8d-4495-9d95-8e24b2a08274 */
#define TEE_SERVICE_FILE_ENCRY                             \
    {                                                      \
        0x54ff868f, 0x0d8d, 0x4495,                        \
        {                                                  \
            0x9d, 0x95, 0x8e, 0x24, 0xb2, 0xa0, 0x82, 0x74 \
        }                                                  \
    }

/* 8780dda1-a49e-45f4-9697-c7ed9e385e83 */
#define TEE_SECIDENTIFICATION1                             \
    {                                                      \
        0x8780dda1, 0xa49e, 0x45f4,                        \
        {                                                  \
            0x96, 0x97, 0xc7, 0xed, 0x9e, 0x38, 0x5e, 0x83 \
        }                                                  \
    }

/* 335129cd-41fa-4b53-9797-5ccb202a52d4 */
#define TEE_SECIDENTIFICATION3                             \
    {                                                      \
        0x335129cd, 0x41fa, 0x4b53,                        \
        {                                                  \
            0x97, 0x97, 0x5c, 0xcb, 0x20, 0x2a, 0x52, 0xd4 \
        }                                                  \
    }

/* 42abc5f0-2d2e-4c3d-8c3f-3499783ca973 */
#define TEE_WEAVER_TA                                 \
    {                                                      \
        0x42abc5f0, 0x2d2e, 0x4c3d,                        \
        {                                                  \
            0x8c, 0x3f, 0x34, 0x99, 0x78, 0x3c, 0xa9, 0x73 \
        }                                                  \
    }

/* 431180bf-7460-4599-a1a7-113df7b1a688 */
#define TEE_REMOTE_PIN                                     \
    {                                                      \
        0x431180bf, 0x7460, 0x4599,                        \
        {                                                  \
            0xa1, 0xa7, 0x11, 0x3d, 0xf7, 0xb1, 0xa6, 0x88 \
        }                                                  \
    }

/* fbcac924-870c-46d0-b101-2c189532ea3a */
#define TEE_SERVICE_STRONGBOX                              \
    {                                                      \
        0xfbcac924, 0x870c, 0x46d0,                        \
        {                                                  \
            0xb1, 0x01, 0x2c, 0x18, 0x95, 0x32, 0xea, 0x3a \
        }                                                  \
    }

/*
 * @ingroup  TEE_COMMON_DATA
 * efuse service
 */
#define TEE_SERVICE_EFUSE                                  \
    {                                                      \
        0x05050505, 0x0505, 0x0505,                        \
        {                                                  \
            0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05 \
        }                                                  \
    }

#define TEE_SERVICE_IMAXCRYPTO                             \
    {                                                      \
        0xd2b09738, 0x6ff6, 0x40d3,                        \
        {                                                  \
            0x9f, 0xde, 0x54, 0x71, 0x9c, 0xde, 0xc3, 0x59 \
        }                                                  \
    }

#define TEE_SERVICE_GATEKEEPER                             \
    {                                                      \
        0x0B0B0B0B, 0x0B0B, 0x0B0B,                        \
        {                                                  \
            0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B \
        }                                                  \
    }

/* f8028dca-aba0-11e6-80f5-76304dec7eb7 */
#define TEE_SERVICE_SECMEM                                 \
    {                                                      \
        0xf8028dca, 0xaba0, 0x11e6,                        \
        {                                                  \
            0x80, 0xf5, 0x76, 0x30, 0x4d, 0xec, 0x7e, 0xb7 \
        }                                                  \
    }

/* ae693f38-8169-4b30-a4b2-7050cf20a620 */
#define TEE_SERVICE_BLOCK_CHAIN                            \
    {                                                      \
        0xae693f38, 0x8169, 0x4b30,                        \
        {                                                  \
            0xa4, 0xb2, 0x70, 0x50, 0xcf, 0x20, 0xa6, 0x20 \
        }                                                  \
    }

/*
 * @ingroup  TEE_COMMON_DATA
 * crypt service
 */
#define TEE_SERVICE_CRYPT                                  \
    {                                                      \
        0x04040404, 0x0404, 0x0404,                        \
        {                                                  \
            0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04 \
        }                                                  \
    }

/* 81449668-008d-4656-9106-c121c9f6c134 */
#define TEE_SERVICE_WFD                                    \
    {                                                      \
        0x81449668, 0x008d, 0x4656,                        \
        {                                                  \
            0x91, 0x06, 0xc1, 0x21, 0xc9, 0xf6, 0xc1, 0x34 \
        }                                                  \
    }

/* c123c643-5b5b-4c9f-9098-bb09564d6eda */
#define TEE_SERVICE_AI_TINY                              \
    {                                                      \
        0xc123c643, 0x5b5b, 0x4c9f,                        \
        {                                                  \
            0x90, 0x98, 0xbb, 0x09, 0x56, 0x4d, 0x6e, 0xda \
        }                                                  \
    }

/* 0069f244-9733-4e8c-98c7-e36cb764a6b6 */
#define TEE_SERVICE_MULTIDRM                           \
{                                                      \
    0x0069f244, 0x9733, 0x4e8c,                        \
    {                                                  \
        0x98, 0xc7, 0xe3, 0x6c, 0xb7, 0x64, 0xa6, 0xb6 \
    }                                                  \
}

/* 744c9cd8-5aec-450c-a9bc-733189d3b3a0 */
#define TEE_SERVICE_HSM_UPGRADE                            \
    {                                                      \
        0x744c9cd8, 0x5aec, 0x450c,                        \
        {                                                  \
            0xa9, 0xbc, 0x73, 0x31, 0x89, 0xd3, 0xb3, 0xa0 \
        }                                                  \
    }

/* 9d420a21-b440-473e-b354-ab9310e2a6d1 */
#define TEE_SERVICE_HSM_BBOX                               \
    {                                                      \
        0x9d420a21, 0xb440, 0x473e,                        \
        {                                                  \
            0xb3, 0x54, 0xab, 0x93, 0x10, 0xe2, 0xa6, 0xd1 \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * product line RPMB key write TA in HSM
 * 6fd66c9c-017c-4610-80da-a665a79b0662
 */
#define TEE_SERVICE_HSM_RPMBKEY                                \
    {                                                      \
        0x6fd66c9c, 0x017c, 0x4610,                        \
        {                                                  \
            0x80, 0xda, 0xa6, 0x65, 0xa7, 0x9b, 0x06, 0x62 \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * product line efuse write and check TA in HSM
 * c97a7f7d-d659-4851-ba79-b0cbf7818959
 */
#define TEE_SERVICE_HSM_EFUSE                                \
    {                                                      \
        0xc97a7f7d, 0xd659, 0x4851,                        \
        {                                                  \
            0xba, 0x79, 0xb0, 0xcb, 0xf7, 0x81, 0x89, 0x59 \
        }                                                  \
    }

/*
 * @ingroup  HSM
 *
 * MDC use flash in HSM
 * e3f99c30-f19d-41f8-87c2-e0274f59cd26
 */
#define TEE_SERVICE_HSM_FLASH                              \
    {                                                      \
        0xe3f99c30, 0xf19d, 0x41f8,                        \
        {                                                  \
            0x87, 0xc2, 0xe0, 0x27, 0x4f, 0x59, 0xcd, 0x26 \
        }                                                  \
    }

/* 3e023098-28c0-4d41-83be-0df7685823df */
#define TEE_SERVICE_BUS_TEST                               \
    {                                                      \
        0x3e023098, 0x28c0, 0x4d41,                        \
        {                                                  \
            0x83, 0xbe, 0x0d, 0xf7, 0x68, 0x58, 0x23, 0xdf \
        }                                                  \
    }

/* 596116b6-1d7c-46d8-b540-eaaa52e75979.sec */
#define TEE_SERVICE_HWSDP                                  \
    {                                                      \
        0x596116b6, 0x1d7c, 0x46d8,                        \
        {                                                  \
            0xb5, 0x40, 0xea, 0xaa, 0x52, 0xe7, 0x59, 0x79 \
        }                                                  \
    }

 /* 5700f837-8b8e-4661-800b-42bb3fc3141f */
#define TEE_SERVICE_SECIVP                                 \
    {                                                      \
        0x5700f837, 0x8b8e, 0x4661,                        \
        {                                                  \
            0x80, 0x0b, 0x42, 0xbb, 0x3f, 0xc3, 0x14, 0x1f \
        }                                                  \
    }

/* 1224acd7-1598-4269-bb11-ad91a3261938 */
#define TEE_SERVICE_AUDI_VKMS                              \
    {                                                      \
        0x1224acd7, 0x1598, 0x4269,                        \
        {                                                  \
            0xbb, 0x11, 0xad, 0x91, 0xa3, 0x26, 0x19, 0x38 \
        }                                                  \
    }
/* MTK binary TA */
#ifdef TEE_SUPPORT_M_DRIVER
#define TEE_SERVICE_TRUSTED_MEM                            \
    {                                                      \
        0x08030000, 0x0000, 0x0000,                        \
        {                                                  \
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 \
        }                                                  \
    }

#define TEE_SERVICE_CMDQ_TA                                \
    {                                                      \
        0x09010000, 0x0000, 0x0000,                        \
        {                                                  \
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 \
        }                                                  \
    }

#define TEE_SERVICE_M4U_TA                                 \
    {                                                      \
        0x98fb95bc, 0xb4bf, 0x42d2,                        \
        {                                                  \
            0x64, 0x73, 0xea, 0xe4, 0x86, 0x90, 0xd7, 0x3a \
        }                                                  \
    }

#define TEE_SERVICE_H264_TA                                \
    {                                                      \
        0x08090000, 0x0000, 0x0000,                        \
        {                                                  \
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 \
        }                                                  \
    }

#endif /* TEE_SUPPORT_M_DRIVER */

#endif /* PLATFORM_PRODUCT_UUID_PUBLIC_H */
