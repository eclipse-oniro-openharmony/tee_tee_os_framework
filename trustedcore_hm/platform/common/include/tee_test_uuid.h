/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee test TA uuid declaration
 * Create: 2020-02-19
 */
#ifndef PLATFORM_TEE_TEST_UUID_H
#define PLATFORM_TEE_TEST_UUID_H

#ifdef DEF_ENG
/*
 * @ingroup  TEE_CONFIG_DATA
 * HELLO_WORLD TA
 * 79b77788-9789-4a7a-a2be-b60155eef5f3
 */
#define TEE_SERVICE_HELLOWORLD                             \
    {                                                      \
        0x79b77788, 0x9789, 0x4a7a,                        \
        {                                                  \
            0xa2, 0xbe, 0xb6, 0x01, 0x55, 0xee, 0xf5, 0xf3 \
        }                                                  \
    }

/* add for ta init test */
#define TA_INIT_TEST_UUID                                  \
    {                                                      \
        0x01234567, 0x89ab, 0xcde0,                        \
        {                                                  \
            0x12, 0x34, 0x56, 0x78, 0x9a, 0x00, 0x00, 0x00 \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 *  KERNEL_MEM_USAGE TA
 * 04040404-9789-4a7a-a2be-b60155eef5f3
 */
#define TEE_SERVICE_KERNELMEMUSAGE                         \
    {                                                      \
        0x04040404, 0x9789, 0x4a7a,                        \
        {                                                  \
            0xa2, 0xbe, 0xb6, 0x01, 0x55, 0xee, 0xf5, 0xf3 \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * TIMER_UT TA
    19B39980-2487-7B84-F41A-BC892262BB3D
 */
#define TEE_SERVICE_TIMER_UT                               \
    {                                                      \
        0x19B39980, 0x2487, 0x7B84,                        \
        {                                                  \
            0xf4, 0x1a, 0xbc, 0x89, 0x22, 0x62, 0xbb, 0x3d \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * PERMISSIONCONTROL_UT TA
 * F1AE5991-F36A-84A4-EE9F-234B37FBBE69
 */
#define TEE_SERVICE_PERMCTRL_UT                            \
    {                                                      \
        0xF1AE5991, 0xF36A, 0x84A4,                        \
        {                                                  \
            0xee, 0x9f, 0x23, 0x4b, 0x37, 0xfb, 0xbe, 0x69 \
        }                                                  \
    }

/* abc12345-1234-1234-1234-123456789abc */
#define TEE_TEST_SERVICE_CRLAGENT                          \
    {                                                      \
        0xabc12345, 0x1234, 0x1234,                        \
        {                                                  \
            0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc \
        }                                                  \
    }

#define HM_TEEOS_TEST                                      \
    {                                                      \
        0x79b77789, 0x9710, 0x4a7b,                        \
        {                                                  \
            0xa3, 0xbf, 0xb7, 0x02, 0x56, 0xef, 0xf6, 0xf4 \
        }                                                  \
    }

/*
 * @ingroup  TEE_COMMON_DATA
 * teeos test API
 */
#define TEE_SERVICE_TEST_API                               \
    {                                                      \
        0x12121212, 0x1212, 0x1212,                        \
        {                                                  \
            0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12 \
        }                                                  \
    }

/*
 * @ingroup  TEE_COMMON_DATA
 * teeos Echo test
 */
#define TEE_SERVICE_ECHO                                   \
    {                                                      \
        0x01010101, 0x0101, 0x0101,                        \
        {                                                  \
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 \
        }                                                  \
    }

/*
 * @ingroup  TEE_COMMON_DATA
 * teeos UT test
 */
#define TEE_SERVICE_UT                                     \
    {                                                      \
        0x03030303, 0x0303, 0x0303,                        \
        {                                                  \
            0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03 \
        }                                                  \
    }

/*
 * @ingroup  TEE_CONFIG_DATA
 *
 * endorsement ta
 * 90925dbc-b85b-4ae3-a813-2dc9b4266da9
 */
#define TEE_SERVICE_ENDORSEMENT                            \
    {                                                      \
        0x90925dbc, 0xb85b, 0x4ae3,                        \
        {                                                  \
            0xa8, 0x13, 0x2d, 0xc9, 0xb4, 0x26, 0x6d, 0xa9 \
        }                                                  \
    }

/* for test dyn ion ta */
#define TEE_SERVICE_TEST_DYNION                            \
    {                                                      \
        0x7f313b2a, 0x68b9, 0x4e92,                        \
        {                                                  \
            0xac, 0xf9, 0x13, 0x3e, 0xbb, 0x54, 0xeb, 0x56 \
        }                                                  \
    }

/* 79b77788-9789-4a7a-a2be-b60155eef5f4 */
#define TEE_SEVICE_VIDEO_TEST                              \
    {                                                      \
        0x79b77788, 0x9789, 0x4a7a,                        \
        {                                                  \
            0xa2, 0xbe, 0xb6, 0x01, 0x55, 0xee, 0xf5, 0xf4 \
        }                                                  \
    }

/* 9cb38838-2766-42be-8b7b-0d184a996061 */
#define TEE_COMMON_TEST_TA1                           \
    {                                                      \
        0x9cb38838, 0x2766, 0x42be,                        \
        {                                                  \
            0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x61 \
        }                                                  \
    }

/* 9cb38838-2766-42be-8b7b-0d184a996062 */
#define TEE_COMMON_TEST_TA2                           \
    {                                                      \
        0x9cb38838, 0x2766, 0x42be,                        \
        {                                                  \
            0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x62 \
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

/* 9cd40404-2766-4a7a-8b7b-0d184a991012 */
#define TEE_INNER_TEST_TA                           \
    {                                                      \
        0x9cd40404, 0x2766, 0x4a7a,                        \
        {                                                  \
            0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x10, 0x12 \
        }                                                  \
    }

#endif

#endif
