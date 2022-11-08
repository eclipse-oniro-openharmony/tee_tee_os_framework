/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#ifndef TEE_INNER_UUID_H
#define TEE_INNER_UUID_H

/*
 * @ingroup  TEE_COMMON_DATA
 *
 * Secure Global Serivce
 */
#define TEE_MISC_DRIVER                                    \
    {                                                      \
        0x5bb40be1, 0x6b49, 0x421c,                        \
        {                                                  \
            0x9d, 0xd5, 0x79, 0xf5, 0xcb, 0xde, 0x3f, 0xb3 \
        }                                                  \
    }

#define TEE_SERVICE_GLOBAL                                 \
    {                                                      \
        0x00000000, 0x0000, 0x0000,                        \
        {                                                  \
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 \
        }                                                  \
    }

#define TEE_SMC_MGR                               \
    {                                                      \
        0x6e1ce639, 0x1e07, 0x4972,                        \
        {                                                  \
            0xa6, 0x63, 0xc0, 0x2c, 0xa4, 0xb4, 0xac, 0x47 \
        }                                                  \
    }

#define TEE_DRV_TIMER                               \
    {                                                      \
        0x0a2917b7, 0xd941, 0x4dde,                        \
        {                                                  \
            0x9d, 0x8a, 0x62, 0x90, 0xbd, 0x13, 0xa9, 0x0e \
        }                                                  \
    }

#define DRVMGR                                     \
    {                                                      \
        0x4b73448d, 0x3423, 0x4162,                        \
        {                                                  \
            0x82, 0xad, 0x29, 0x43, 0x6c, 0x68, 0x05, 0x8f \
        }                                                  \
    }

/*
 * @ingroup  TEE_COMMON_DATA
 *
 * Secure Storage Service
 */
#define TEE_SERVICE_STORAGE                                \
    {                                                      \
        0x02020202, 0x0202, 0x0202,                        \
        {                                                  \
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 \
        }                                                  \
    }

/*
 * @ingroup  TEE_COMMON_DATA
 *
 * KeyMaster Service
 */
#define TEE_SERVICE_KEYMASTER                              \
    {                                                      \
        0x07070707, 0x0707, 0x0707,                        \
        {                                                  \
            0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07 \
        }                                                  \
    }

#define TEE_SERVICE_GATEKEEPER                             \
    {                                                      \
        0x0B0B0B0B, 0x0B0B, 0x0B0B,                        \
        {                                                  \
            0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B \
        }                                                  \
    }

#define TEE_SERVICE_SD                                     \
    {                                                      \
        0x603e1482, 0xa5c6, 0x5582,                        \
        {                                                  \
            0xb9, 0x19, 0xd3, 0x01, 0x6a, 0x17, 0x1f, 0xc5 \
        }                                                  \
    }

#define TEE_SERVICE_SSA                                    \
    {                                                      \
        0x999286b9, 0x54da, 0x4235,                        \
        {                                                  \
            0x9e, 0x77, 0x96, 0xe8, 0x1f, 0xea, 0x1e, 0xe4 \
        }                                                  \
    }

/* c2c44f8b-022a-4bbb-90c4-117aec059cc8 */
#define TEE_SERVICE_BIO                                    \
    {                                                      \
        0xc2c44f8b, 0x022a, 0x4bbb,                        \
        {                                                  \
            0x90, 0xc4, 0x11, 0x7a, 0xec, 0x05, 0x9c, 0xc8 \
        }                                                  \
    }

/* 9d54c432-8b7d-4dba-a39d-18631365f33c */
#define TEE_SERVICE_ROT                                    \
    {                                                      \
        0x9d54c432, 0x8b7d, 0x4dba,                        \
        {                                                  \
            0xa3, 0x9d, 0x18, 0x63, 0x13, 0x65, 0xf3, 0x3c \
        }                                                  \
    }

/* 9db060b1-6828-5070-9afc-daabb4b1e3ad */
#define TEE_SERVICE_CRYPTOAGENT                        \
{                                                      \
    0x9db060b1, 0x6828, 0x5070,                        \
    {                                                  \
        0x9a, 0xfc, 0xda, 0xab, 0xb4, 0xb1, 0xe3, 0xad \
    }                                                  \
}
/* edce4375-848c-4680-ada3-383a5b9ffb84 */
#define TEE_SERVICE_ART                                    \
    {                                                      \
        0xedce4375, 0x848c, 0x4680,                        \
        {                                                  \
            0xad, 0xa3, 0x38, 0x3a, 0x5b, 0x9f, 0xfb, 0x84 \
        }                                                  \
    }

/* 1074b0ca-3efb-42c9-ab63-78711e542b1b */
#define TEE_SERVICE_PERM                                   \
    {                                                      \
        0x1074b0ca, 0x3efb, 0x42c9,                        \
        {                                                  \
            0xab, 0x63, 0x78, 0x71, 0x1e, 0x54, 0x2b, 0x1b \
        }                                                  \
    }

/* 91f0cf6b-bd4b-456e-862d-3fa61ab1a4ac */
#define TEE_SERVICE_SE                                     \
    {                                                      \
        0x91f0cf6b, 0xbd4b, 0x456e,                        \
        {                                                  \
            0x86, 0x2d, 0x3f, 0xa6, 0x1a, 0xb1, 0xa4, 0xac \
        }                                                  \
    }

/* 0db8b999-e0e1-42dd-b6fe-61629cec01fa */
#define TEE_SERVICE_CRLAGENT                               \
    {                                                      \
        0x0db8b999, 0xe0e1, 0x42dd,                        \
        {                                                  \
            0xb6, 0xfe, 0x61, 0x62, 0x9c, 0xec, 0x01, 0xfa \
        }                                                  \
    }

/* 9a5c802c-386f-4081-8c5d-de19bda0239b */
#define TEE_SERVICE_HUK                                    \
    {                                                      \
        0x9a5c802c, 0x386f, 0x4081,                        \
        {                                                  \
            0x8c, 0x5d, 0xde, 0x19, 0xbd, 0xa0, 0x23, 0x9b \
        }                                                  \
    }

/*
 * @ingroup  TEE_COMMON_DATA
 *
 * Notification task
 */
#define TEE_SERVICE_REET                                   \
    {                                                      \
        0x0A0A0A0A, 0x0A0A, 0x0A0A,                        \
        {                                                  \
            0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A \
        }                                                  \
    }

/* 8f3cf731-55c8-4d57-b609-66a2a9516a51 */
#define TEE_SERVICE_ATTESTATION_TA                         \
    {                                                      \
        0x8f3cf731, 0x55c8, 0x4d57,                        \
        {                                                  \
            0xb6, 0x09, 0x66, 0xa2, 0xa9, 0x51, 0x6a, 0x51 \
        }                                                  \
    }

/* 2a38b99f-7c7e-4c5e-b5d2-1f630d3f25b7 */
#define TEE_SERVICE_HSM                                    \
    {                                                      \
        0x2a38b99f, 0x7c7e, 0x4c5e,                        \
        {                                                  \
            0xb5, 0xd2, 0x1f, 0x63, 0x0d, 0x3f, 0x25, 0xb7 \
        }                                                  \
    }

/* aaa862d1-22fe-4609-a4ee-8667f6538f18 */
#define TEE_SERVICE_SEM                                    \
    {                                                      \
        0xaaa862d1, 0x22fe, 0x4609,                        \
        {                                                  \
            0xa4, 0xee, 0x86, 0x67, 0xf6, 0x53, 0x8f, 0x18 \
        }                                                  \
    }

#define TEE_SERVICE_DPHDCP                                 \
    {                                                      \
        0xed21ae9e, 0x607e, 0x4ff9,                        \
        {                                                  \
            0xaf, 0x6d, 0x93, 0x4d, 0x21, 0xe0, 0x34, 0xdb \
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

/* d2c2ed9b-267e-40a4-960a-071699c9222e */
#define TEE_SERVICE_KDS                                    \
    {                                                      \
        0xd2c2ed9b, 0x267e, 0x40a4,                        \
        {                                                  \
            0x96, 0x0a, 0x07, 0x16, 0x99, 0xc9, 0x22, 0x2e \
        }                                                  \
    }

/*
 * @ingroup  TEE_COMMON_DATA
 *
 * HDCP Secure Storage Service
 */
#define TEE_SERVICE_HDCP                                   \
    {                                                      \
        0x06060606, 0x0606, 0x0606,                        \
        {                                                  \
            0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06 \
        }                                                  \
    }

/* d902f26f-7153-4e46-a79c-94844af8b007 */
#define TEE_SERVICE_VLTMM_SRV                              \
    {                                                      \
        0xd902f26f, 0x7153, 0x4e46,                        \
        {                                                  \
            0xa7, 0x9c, 0x94, 0x84, 0x4a, 0xf8, 0xb0, 0x07 \
        }                                                  \
    }
/*
 * @ingroup  TEE_COMMON_DATA
 *
 * KMS key operation service
 */
#define TEE_SERVICE_KMS                                    \
    {                                                      \
        0x4c223dbe, 0x71c8, 0x4823,                        \
        {                                                  \
            0x82, 0x6b, 0x58, 0xe9, 0xd5, 0x92, 0x66, 0x66 \
        }                                                  \
    }

/* 9cd40404-2766-4a7a-8b7b-0d184a991011 */
#define TEE_INNER_TEST_SERVICE                           \
    {                                                      \
        0x9cd40404, 0x2766, 0x4a7a,                        \
        {                                                  \
            0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x10, 0x11 \
        }                                                  \
    }
/* 2427f879-4655-4367-8231-e58e2945c9b8 */
#define CRYPTOMGR                                     \
    {                                                      \
        0x2427f879, 0x4655, 0x4367,                        \
        {                                                  \
            0x82, 0x31, 0xe5, 0x8e, 0x29, 0x45, 0xc9, 0xb8 \
        }                                                  \
    }
#endif
