/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: ecdsa
 * Author: hsan
 * Create: 2017-4-11
 * History: 2017-4-11初稿完成
 *          2019-1-31 hsan code restyle
 */

#include <hisilicon/chip/level_2/hi_sdk_l2.h>

#include "hi_sec_api.h"
#include "hi_sec_pke.h"

#define HI_SEC_PKE_FAILURE_FLAG_UNLIMIT_POINT   0x4
#define HI_SEC_PKE_ECDSA_576BIT   72 //576bit 高位补0

struct hi_ecdsa_oval_param_ptr_s {
	hi_ushort16 len;
	hi_uchar8 *p;
	hi_uchar8 *n;
	hi_uchar8 *a;
	hi_uchar8 *b;
	hi_uchar8 *gx;
	hi_uchar8 *gy;
};

struct hi_ecdsa_sign_vari_tmp_s {
	hi_uint32 two_len_n;
	hi_uint32 datalen;
	hi_uchar8 *n_576_data;
	hi_uchar8 *two_two_len_n;
	hi_uchar8 *upper_n;
	hi_uchar8 *k;
	hi_uchar8 *r1;
	hi_uchar8 *rx;
	hi_uchar8 *ry;
	hi_uchar8 *me;
	hi_uchar8 *mr;
	hi_uchar8 *md;
	hi_uchar8 *mrd;
	hi_uchar8 *y;
	hi_uchar8 *mk;
	hi_uchar8 *mkni;
	hi_uchar8 *ms;
	hi_uchar8 *zero;
	hi_uchar8 *one;
	hi_uchar8 *upper_e;
	hi_uchar8 *upper_s;
};

struct hi_ecdsa_verify_formula_s {
	hi_uint32 two_len_n;
	hi_uint32 datalen;
	hi_uchar8 *n_576_data;
	hi_uchar8 *two_two_len_n;
	hi_uchar8 *upper_n;
	hi_uchar8 *ms;
	hi_uchar8 *msni;
	hi_uchar8 *upper_e;
	hi_uchar8 *m_upper_e;
	hi_uchar8 *mu1;
	hi_uchar8 *u1;
	hi_uchar8 *mr;
	hi_uchar8 *mu2;
	hi_uchar8 *u2;
	hi_uchar8 *u1gx;
	hi_uchar8 *u1gy;
	hi_uchar8 *u2qx;
	hi_uchar8 *u2qy;
	hi_uchar8 *rx;
	hi_uchar8 *ry;
	hi_uchar8 *v;
	hi_uchar8 *zero;
	hi_uchar8 *one;
	hi_uchar8 *upper_s;
};

struct hi_ecdsa_keychk_formula_s {
	hi_uint32 two_len_n;
	hi_uint32 datalen;
	hi_uchar8 *p_576_data;
	hi_uchar8 *two_two_len_p;
	hi_uchar8 *upper_p;
	hi_uchar8 *mx;
	hi_uchar8 *my;
	hi_uchar8 *ma;
	hi_uchar8 *mb;
	hi_uchar8 *mx2;
	hi_uchar8 *mx3;
	hi_uchar8 *max;
	hi_uchar8 *mx3p;
	hi_uchar8 *m_upper_z;
	hi_uchar8 *my2;
	hi_uchar8 *diff;
	hi_uchar8 *zero;
	hi_uchar8 *rx;
	hi_uchar8 *ry;
};

enum hi_sec_pke_ecc_param_e {
	HI_SEC_PKE_ECC_P_E = 0,
	HI_SEC_PKE_ECC_N_E,
	HI_SEC_PKE_ECC_A_E,
	HI_SEC_PKE_ECC_B_E,
	HI_SEC_PKE_ECC_GX_E,
	HI_SEC_PKE_ECC_GY_E,
	HI_SEC_PKE_ECC_PARAM_NUM,
};

static hi_uchar8 g_ecc192[HI_SEC_PKE_ECC_PARAM_NUM][HI_SEC_PKE_ECDSA_256BIT] = {
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    }, // p
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x99, 0xDE, 0xF8, 0x36, 0x14, 0x6B, 0xC9, 0xB1, 0xB4, 0xD2, 0x28, 0x31
    }, // n
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
    }, // a -3
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x21, 0x05, 0x19, 0xe5, 0x9c, 0x80, 0xe7,
        0x0f, 0xa7, 0xe9, 0xab, 0x72, 0x24, 0x30, 0x49, 0xfe, 0xb8, 0xde, 0xec, 0xc1, 0x46, 0xb9, 0xb1
    }, // b
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x8d, 0xa8, 0x0e, 0xb0, 0x30, 0x90, 0xf6,
        0x7c, 0xbf, 0x20, 0xeb, 0x43, 0xa1, 0x88, 0x00, 0xf4, 0xff, 0x0a, 0xfd, 0x82, 0xff, 0x10, 0x12
    }, // Gx
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x19, 0x2b, 0x95, 0xff, 0xc8, 0xda, 0x78,
        0x63, 0x10, 0x11, 0xed, 0x6b, 0x24, 0xcd, 0xd5, 0x73, 0xf9, 0x77, 0xa1, 0x1e, 0x79, 0x48, 0x11
    }, // Gy
    // h = 1
};

static hi_uchar8 g_ecc224[HI_SEC_PKE_ECC_PARAM_NUM][HI_SEC_PKE_ECDSA_256BIT] = {
    {
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    }, // p
    {
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0x16, 0xA2, 0xE0, 0xB8, 0xF0, 0x3E, 0x13, 0xDD, 0x29, 0x45, 0x5C, 0x5C, 0x2A, 0x3D
    }, // n
    {
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE
    }, // a -3
    {
        0x00, 0x00, 0x00, 0x00, 0xb4, 0x05, 0x0a, 0x85, 0x0c, 0x04, 0xb3, 0xab, 0xf5, 0x41, 0x32, 0x56,
        0x50, 0x44, 0xb0, 0xb7, 0xd7, 0xbf, 0xd8, 0xba, 0x27, 0x0b, 0x39, 0x43, 0x23, 0x55, 0xff, 0xb4
    }, // b
    {
        0x00, 0x00, 0x00, 0x00, 0xb7, 0x0e, 0x0c, 0xbd, 0x6b, 0xb4, 0xbf, 0x7f, 0x32, 0x13, 0x90, 0xb9,
        0x4a, 0x03, 0xc1, 0xd3, 0x56, 0xc2, 0x11, 0x22, 0x34, 0x32, 0x80, 0xd6, 0x11, 0x5c, 0x1d, 0x21
    }, // Gx
    {
        0x00, 0x00, 0x00, 0x00, 0xbd, 0x37, 0x63, 0x88, 0xb5, 0xf7, 0x23, 0xfb, 0x4c, 0x22, 0xdf, 0xe6,
        0xcd, 0x43, 0x75, 0xa0, 0x5a, 0x07, 0x47, 0x64, 0x44, 0xd5, 0x81, 0x99, 0x85, 0x00, 0x7e, 0x34
    }, // Gy
    // h = 1
};

static hi_uchar8 g_ecc256[HI_SEC_PKE_ECC_PARAM_NUM][HI_SEC_PKE_ECDSA_256BIT] = {
    {
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    }, // p
    {
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B, 0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23
    }, // n
    {
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
    }, // a
    {
        0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
        0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93
    }, // b
    {
        0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
        0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7
    }, // Gx
    {
        0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
        0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0
    } // Gy
};

static hi_uchar8 g_ecc384[HI_SEC_PKE_ECC_PARAM_NUM][HI_SEC_PKE_ECDSA_384BIT] = {
    {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
    }, // p
    {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
        0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73
    }, // n
    {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC
    }, // a -3
    {
        0xb3, 0x31, 0x2f, 0xa7, 0xe2, 0x3e, 0xe7, 0xe4, 0x98, 0x8e, 0x05, 0x6b, 0xe3, 0xf8, 0x2d, 0x19,
        0x18, 0x1d, 0x9c, 0x6e, 0xfe, 0x81, 0x41, 0x12, 0x03, 0x14, 0x08, 0x8f, 0x50, 0x13, 0x87, 0x5a,
        0xc6, 0x56, 0x39, 0x8d, 0x8a, 0x2e, 0xd1, 0x9d, 0x2a, 0x85, 0xc8, 0xed, 0xd3, 0xec, 0x2a, 0xef
    }, // b
    {
        0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e, 0xf3, 0x20, 0xad, 0x74,
        0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98, 0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38,
        0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29, 0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7
    }, // Gx
    {
        0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf, 0x92, 0x92, 0xdc, 0x29,
        0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c, 0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0,
        0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f
    }, // Gy
    // h = 1
};

static hi_uchar8 g_ecc521[HI_SEC_PKE_ECC_PARAM_NUM][HI_SEC_PKE_ECDSA_576BIT] = {
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    }, // p
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83, 0xBF, 0x2F, 0x96, 0x6B,
        0x7F, 0xCC, 0x01, 0x48, 0xF7, 0x09, 0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8,
        0x89, 0x9C, 0x47, 0xAE, 0xBB, 0x6F, 0xB7, 0x1E, 0x91, 0x38, 0x64, 0x09
    }, // n
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
    }, // a
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x95, 0x3E, 0xB9, 0x61,
        0x8E, 0x1C, 0x9A, 0x1F, 0x92, 0x9A, 0x21, 0xA0, 0xB6, 0x85, 0x40, 0xEE,
        0xA2, 0xDA, 0x72, 0x5B, 0x99, 0xB3, 0x15, 0xF3, 0xB8, 0xB4, 0x89, 0x91,
        0x8E, 0xF1, 0x09, 0xE1, 0x56, 0x19, 0x39, 0x51, 0xEC, 0x7E, 0x93, 0x7B,
        0x16, 0x52, 0xC0, 0xBD, 0x3B, 0xB1, 0xBF, 0x07, 0x35, 0x73, 0xDF, 0x88,
        0x3D, 0x2C, 0x34, 0xF1, 0xEF, 0x45, 0x1F, 0xD4, 0x6B, 0x50, 0x3F, 0x00
    }, // b
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0x85, 0x8E, 0x06, 0xB7,
        0x04, 0x04, 0xE9, 0xCD, 0x9E, 0x3E, 0xCB, 0x66, 0x23, 0x95, 0xB4, 0x42,
        0x9C, 0x64, 0x81, 0x39, 0x05, 0x3F, 0xB5, 0x21, 0xF8, 0x28, 0xAF, 0x60,
        0x6B, 0x4D, 0x3D, 0xBA, 0xA1, 0x4B, 0x5E, 0x77, 0xEF, 0xE7, 0x59, 0x28,
        0xFE, 0x1D, 0xC1, 0x27, 0xA2, 0xFF, 0xA8, 0xDE, 0x33, 0x48, 0xB3, 0xC1,
        0x85, 0x6A, 0x42, 0x9B, 0xF9, 0x7E, 0x7E, 0x31, 0xC2, 0xE5, 0xBD, 0x66
    }, // Gx
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x18, 0x39, 0x29, 0x6A, 0x78,
        0x9A, 0x3B, 0xC0, 0x04, 0x5C, 0x8A, 0x5F, 0xB4, 0x2C, 0x7D, 0x1B, 0xD9,
        0x98, 0xF5, 0x44, 0x49, 0x57, 0x9B, 0x44, 0x68, 0x17, 0xAF, 0xBD, 0x17,
        0x27, 0x3E, 0x66, 0x2C, 0x97, 0xEE, 0x72, 0x99, 0x5E, 0xF4, 0x26, 0x40,
        0xC5, 0x50, 0xB9, 0x01, 0x3F, 0xAD, 0x07, 0x61, 0x35, 0x3C, 0x70, 0x86,
        0xA2, 0x72, 0xC2, 0x40, 0x88, 0xBE, 0x94, 0x76, 0x9F, 0xD1, 0x66, 0x50
    }, // Gy
    // h = 1
};

static hi_void hi_ecdsa_get_oval_192bit(struct hi_ecdsa_oval_param_ptr_s *oval)
{
	oval->p  = (hi_uchar8 *)g_ecc192[HI_SEC_PKE_ECC_P_E];
	oval->n  = (hi_uchar8 *)g_ecc192[HI_SEC_PKE_ECC_N_E];
	oval->a  = (hi_uchar8 *)g_ecc192[HI_SEC_PKE_ECC_A_E];
	oval->b  = (hi_uchar8 *)g_ecc192[HI_SEC_PKE_ECC_B_E];
	oval->gx = (hi_uchar8 *)g_ecc192[HI_SEC_PKE_ECC_GX_E];
	oval->gy = (hi_uchar8 *)g_ecc192[HI_SEC_PKE_ECC_GY_E];
}

static hi_void hi_ecdsa_get_oval_224bit(struct hi_ecdsa_oval_param_ptr_s *oval)
{
	oval->p  = (hi_uchar8 *)g_ecc224[HI_SEC_PKE_ECC_P_E];
	oval->n  = (hi_uchar8 *)g_ecc224[HI_SEC_PKE_ECC_N_E];
	oval->a  = (hi_uchar8 *)g_ecc224[HI_SEC_PKE_ECC_A_E];
	oval->b  = (hi_uchar8 *)g_ecc224[HI_SEC_PKE_ECC_B_E];
	oval->gx = (hi_uchar8 *)g_ecc224[HI_SEC_PKE_ECC_GX_E];
	oval->gy = (hi_uchar8 *)g_ecc224[HI_SEC_PKE_ECC_GY_E];
}

static hi_void hi_ecdsa_get_oval_256bit(struct hi_ecdsa_oval_param_ptr_s *oval)
{
	oval->p  = (hi_uchar8 *)g_ecc256[HI_SEC_PKE_ECC_P_E];
	oval->n  = (hi_uchar8 *)g_ecc256[HI_SEC_PKE_ECC_N_E];
	oval->a  = (hi_uchar8 *)g_ecc256[HI_SEC_PKE_ECC_A_E];
	oval->b  = (hi_uchar8 *)g_ecc256[HI_SEC_PKE_ECC_B_E];
	oval->gx = (hi_uchar8 *)g_ecc256[HI_SEC_PKE_ECC_GX_E];
	oval->gy = (hi_uchar8 *)g_ecc256[HI_SEC_PKE_ECC_GY_E];
}

static hi_void hi_ecdsa_get_oval_384bit(struct hi_ecdsa_oval_param_ptr_s *oval)
{
	oval->p  = (hi_uchar8 *)g_ecc384[HI_SEC_PKE_ECC_P_E];
	oval->n  = (hi_uchar8 *)g_ecc384[HI_SEC_PKE_ECC_N_E];
	oval->a  = (hi_uchar8 *)g_ecc384[HI_SEC_PKE_ECC_A_E];
	oval->b  = (hi_uchar8 *)g_ecc384[HI_SEC_PKE_ECC_B_E];
	oval->gx = (hi_uchar8 *)g_ecc384[HI_SEC_PKE_ECC_GX_E];
	oval->gy = (hi_uchar8 *)g_ecc384[HI_SEC_PKE_ECC_GY_E];
}

static hi_void hi_ecdsa_get_oval_521bit(struct hi_ecdsa_oval_param_ptr_s *oval)
{
	oval->p  = (hi_uchar8 *)g_ecc521[HI_SEC_PKE_ECC_P_E];
	oval->n  = (hi_uchar8 *)g_ecc521[HI_SEC_PKE_ECC_N_E];
	oval->a  = (hi_uchar8 *)g_ecc521[HI_SEC_PKE_ECC_A_E];
	oval->b  = (hi_uchar8 *)g_ecc521[HI_SEC_PKE_ECC_B_E];
	oval->gx = (hi_uchar8 *)g_ecc521[HI_SEC_PKE_ECC_GX_E];
	oval->gy = (hi_uchar8 *)g_ecc521[HI_SEC_PKE_ECC_GY_E];
}

/* ECDSA参数获取. 算法位宽,有效224/256/384/521bit, 即28/32/48/66(高位补齐)bytes */
static hi_int32 hi_sec_pke_ecdsa_param_get(hi_uint32 len,
	struct hi_ecdsa_oval_param_ptr_s *oval)
{
	oval->len = len;

	switch (oval->len) {
	case HI_SEC_PKE_ECDSA_192BIT:
		hi_ecdsa_get_oval_192bit(oval);
		break;
	case HI_SEC_PKE_ECDSA_224BIT:
		hi_ecdsa_get_oval_224bit(oval);
		break;
	case HI_SEC_PKE_ECDSA_256BIT:
		hi_ecdsa_get_oval_256bit(oval);
		break;
	case HI_SEC_PKE_ECDSA_384BIT:
		hi_ecdsa_get_oval_384bit(oval);
		break;
	case HI_SEC_PKE_ECDSA_521BIT:
		hi_ecdsa_get_oval_521bit(oval);
		break;
	default:
		hi_pke_systrace(HI_RET_INVALID_PARA, 0, 0, 0, 0);
		return HI_RET_INVALID_PARA;
	}

	return HI_RET_SUCC;
}


/* 不足256bit的数据,补足. 高位填充0 */
static hi_int32 hi_sec_pke_data_pading(hi_uchar8 **data,
	hi_uint32 len_in, hi_uint32 *len_out)
{
	hi_uchar8 *data_padded = HI_NULL;
	hi_uint32 len_padded;

	if (len_in == HI_SEC_PKE_ECDSA_192BIT ||
		len_in == HI_SEC_PKE_ECDSA_224BIT) {
		len_padded = HI_SEC_PKE_ECDSA_256BIT;
	} else if (len_in == HI_SEC_PKE_ECDSA_521BIT) {
		len_padded = HI_SEC_PKE_ECDSA_576BIT;
	} else {
		*len_out = len_in;
		return HI_RET_SUCC;
	}

	data_padded = hi_malloc(len_padded);
	if (data_padded == HI_NULL) {
		hi_pke_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
		return HI_RET_MALLOC_FAIL;
	}

	hi_memset(data_padded, 0, len_padded);
	hi_memcpy((data_padded + len_padded - len_in), *data, len_in);

	*data = data_padded;
	*len_out = len_padded;
	hi_pke_systrace(HI_RET_SUCC, 0, 0, 0, 0);
	return HI_RET_SUCC;
}

/* 释放pading缓存 */
static hi_void hi_sec_pke_data_pading_free(hi_uchar8 **data, hi_uint32 len)
{
	if (len == HI_SEC_PKE_ECDSA_256BIT || len == HI_SEC_PKE_ECDSA_384BIT)
		return;

	if (*data)
		hi_free(*data);

	*data = HI_NULL;
	return;
}

static hi_void hi_ecdsa_req_trans(
	struct hi_sec_ecdsa_req *req_in,
	struct hi_sec_ecdsa_req *req_out)
{
	if (req_in == HI_NULL || req_out == HI_NULL)
		return;

	req_out->d  = req_in->d;
	req_out->m  = req_in->m;
	req_out->qx = req_in->qx;
	req_out->qy = req_in->qy;
	req_out->sx = req_in->sx;
	req_out->sy = req_in->sy;
	return;
}

//static hi_int32 hi_ecdsa_sign_chk_param(struct hi_sec_ecdsa_req *req)
//{
//	if (req == HI_NULL || req->m == HI_NULL || req->d == HI_NULL ||
//		req->sx == HI_NULL || req->sy == HI_NULL) {
//		hi_pke_systrace(HI_RET_NULLPTR, 0, 0, 0, 0);
//		return HI_RET_NULLPTR;
//	}
//	return HI_RET_SUCC;
//}

//static hi_void hi_ecdsa_pading_free_mdk(struct hi_sec_ecdsa_req *req,
//	hi_uint32 free_k)
//{
//	hi_uint32 len = req->key_len;
//
//	hi_sec_pke_data_pading_free(&req->m, len);
//	hi_sec_pke_data_pading_free(&req->d, len);
//	if (free_k)
//		hi_sec_pke_data_pading_free(&req->k, len);
//}

static hi_int32 hi_ecdsa_sign_tmp_init(
	struct hi_ecdsa_sign_vari_tmp_s *tmp, hi_uint32 keylen)
{
	tmp->two_len_n = keylen * 2 + 8;
	tmp->datalen = keylen * 15  + tmp->two_len_n * 3;

	tmp->n_576_data = (hi_uchar8 *)hi_malloc(tmp->datalen);
	if (tmp->n_576_data == HI_NULL) {
		hi_pke_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
		return HI_RET_MALLOC_FAIL;
	}
	hi_memset(tmp->n_576_data, 0, tmp->datalen);

	tmp->two_two_len_n = tmp->n_576_data + tmp->two_len_n;
	tmp->upper_n = tmp->two_two_len_n + tmp->two_len_n;
	tmp->k = tmp->upper_n + tmp->two_len_n;

	tmp->r1 = tmp->k + keylen;
	tmp->rx = tmp->r1 + keylen;
	tmp->ry = tmp->rx + keylen;
	tmp->me = tmp->ry + keylen;
	tmp->mr = tmp->me + keylen;
	tmp->md = tmp->mr + keylen;
	tmp->mrd = tmp->md + keylen;
	tmp->y = tmp->mrd + keylen;
	tmp->mk = tmp->y + keylen;
	tmp->mkni = tmp->mk + keylen;
	tmp->ms = tmp->mkni + keylen;
	tmp->zero = tmp->ms + keylen;
	tmp->one = tmp->zero + keylen;
	tmp->upper_e = tmp->one + keylen;
	tmp->upper_s = tmp->upper_e + keylen;

	tmp->one[keylen - 1] = 0x1;

	return HI_RET_SUCC;
}

/* 计算 R = k * G */
static hi_int32 hi_ecdsa_sign_pm_calc_rxy(
	struct hi_ecdsa_oval_param_ptr_s *oval,
	struct hi_ecdsa_sign_vari_tmp_s *tmp, hi_uint32 keylen)
{
	hi_int32 ret;
	struct hi_pke_ecc_pointmulti_s pm;

	pm.k = tmp->k; /* k */

	pm.p = oval->p;
	pm.n = oval->n;
	pm.a = oval->a;
	pm.b = oval->b;
	pm.gx = oval->gx;
	pm.gy = oval->gy;
	pm.px = oval->gx;
	pm.py = oval->gy;
	pm.len = keylen;

	pm.rx = tmp->rx;
	pm.ry = tmp->ry;
	ret = hi_sec_pke_ecc_pointmulti(&pm);

	return ret;
}

static hi_int32 hi_ecdsa_sign_step1to4(
	struct hi_ecdsa_oval_param_ptr_s *oval,
	struct hi_ecdsa_sign_vari_tmp_s *tmp,
	struct hi_sec_ecdsa_req *req, hi_uint32 keylen)
{
	hi_int32 ret;
	hi_uchar8 *k_origin = HI_NULL;
	hi_uchar8 *n1_data = HI_NULL;
	hi_uint32 len = req->key_len;

	k_origin = tmp->k;
	n1_data = oval->n + keylen - len; /* 不需要n高位补的0 */

	do {
		/* 1.软件自己生成一个随机数k， 其取值范围为[1,n-1]； */
		ret = hi_sec_pke_random_get(n1_data, len, tmp->k);
		if (ret != HI_RET_SUCC) 
			goto hi_ecdsa_sign_step1to4_free_n_md;

		ret = hi_sec_pke_data_pading(&tmp->k, len, &keylen);
		if (ret != HI_RET_SUCC) 
			goto hi_ecdsa_sign_step1to4_free_n_md;

		/* 2.软件配置点乘 R=k*G； */
		ret = hi_ecdsa_sign_pm_calc_rxy(oval, tmp, keylen);
		if (ret != HI_RET_SUCC) 
			goto hi_ecdsa_sign_step1to4_free_k_n_md;

		/* 3.软件配置模加r = (xR + 0) mod n，其中xR为R的x坐标 */
		ret = hi_sec_pke_modadd(tmp->rx, tmp->zero, oval->n,
			keylen, tmp->r1);
		if (ret != HI_RET_SUCC) 
			goto hi_ecdsa_sign_step1to4_free_k_n_md;

		/* 4.软件判断r是否为全0，如果为全0，则跳入步骤1 */
		if (hi_memcmp(tmp->r1, tmp->zero, keylen) == 0) {
			hi_sec_pke_data_pading_free(&tmp->k, len);
			tmp->k = k_origin;
		} else {
			break;
		}
	} while (1);

	hi_memcpy(req->sx, (tmp->r1 + keylen - len), len); /* 输出 r */

	hi_pke_systrace(HI_RET_SUCC, 0, 0, 0, 0);
	return HI_RET_SUCC;

hi_ecdsa_sign_step1to4_free_k_n_md:
	hi_sec_pke_data_pading_free(&tmp->k, len);

hi_ecdsa_sign_step1to4_free_n_md:
	hi_free(tmp->n_576_data);
	tmp->n_576_data = HI_NULL;

	hi_sec_pke_data_pading_free(&req->d, len);
	hi_sec_pke_data_pading_free(&req->m, len);
	hi_pke_systrace(ret, 0, 0, 0, 0);
	return ret;
}

/*
* 7.软件配置基本模N= (2^(2len_n)) mod n；
* 注：如果len_n小于256则统一按照256位宽处理，下同；
* 基本模的长度需按位宽大者的长度进行配置，不足则高位补零；
*/
static hi_int32 hi_ecdsa_sign_calc_uppern_mod(
	struct hi_ecdsa_oval_param_ptr_s *oval,
	struct hi_ecdsa_sign_vari_tmp_s *tmp,
	hi_uint32 keylen)
{
	hi_int32 ret;
	hi_uchar8 *n_576_buf = HI_NULL;
	hi_uchar8 *a = HI_NULL;
	hi_uchar8 *p = HI_NULL;

	n_576_buf = tmp->n_576_data + tmp->two_len_n - keylen;

	hi_memcpy(n_576_buf, oval->n, keylen);
	tmp->two_two_len_n[tmp->two_len_n - keylen * 2 - 1] = 0x1;

	/* 公式 N = (2^(2len_n)) mod n */
	a = tmp->two_two_len_n; /* 赋值 a = (2^(2len_n)) */
	p = tmp->n_576_data;    /* 赋值 p = n_576_data */

	/* 计算c = a mod p */
	ret = hi_sec_pke_mod(a, p, tmp->two_len_n, tmp->upper_n);
	return ret;
}

static hi_int32 hi_ecdsa_sign_param_init(
	struct hi_sec_ecdsa_req *req,
	struct hi_ecdsa_oval_param_ptr_s *oval_param, hi_uint32 *keylen)
{
	hi_int32 ret;
	hi_uint32 len;

	if (req == HI_NULL || req->m == HI_NULL || req->d == HI_NULL ||
		req->sx == HI_NULL || req->sy == HI_NULL) {
		hi_pke_systrace(HI_RET_NULLPTR, 0, 0, 0, 0);
		return HI_RET_NULLPTR;
	}

	len = req->key_len;

	ret = hi_sec_pke_ecdsa_param_get(len, oval_param); /* 获取椭圆参数 */
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	ret = hi_sec_pke_data_pading(&req->m, len, keylen);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	ret = hi_sec_pke_data_pading(&req->d, len, keylen);
	if (ret != HI_RET_SUCC) {
		hi_sec_pke_data_pading_free(&req->m, len);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	hi_pke_systrace(ret, 0, 0, 0, 0);
	return ret;
}

static hi_int32 hi_ecdsa_sign_step9to17(
	struct hi_ecdsa_sign_vari_tmp_s *tmp,
	struct hi_sec_ecdsa_req *req, hi_uchar8 *n, hi_uint32 keylen)
{
	hi_int32 ret;

	/* 9.软件配置模乘mE= MM(n, E, N)
	 * 注：模乘函数MM对应5.7.3节的模乘mE = E * N mod n，下同
	 */
	ret = hi_sec_pke_modmulti(tmp->upper_e, tmp->upper_n, n,
		keylen, tmp->me);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 10.软件配置模乘mr= MM(n, r, N)； */
	ret = hi_sec_pke_modmulti(tmp->r1, tmp->upper_n, n, keylen, tmp->mr);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 11.软件配置模乘mdu=MM(n, du, N)； */
	ret = hi_sec_pke_modmulti(req->d, tmp->upper_n, n, keylen, tmp->md);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 12.软件配置模乘mrdu= MM(n, mdu, mr)； */
	ret = hi_sec_pke_modmulti(tmp->md, tmp->mr, n, keylen, tmp->mrd);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}
	
	/* 13.软件配置模加y=(mE+mrdu) mod n； */
	ret = hi_sec_pke_modadd(tmp->me, tmp->mrd, n, keylen, tmp->y);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 14.软件配置模乘mk=MM(n, k, N)； */
	ret = hi_sec_pke_modmulti(tmp->k, tmp->upper_n, n, keylen, tmp->mk);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 15.软件配置模逆mkni=mk-1 mod n； */
	ret = hi_sec_pke_modinvers(tmp->mk, n, keylen, tmp->mkni);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 16.软件配置模乘ms=MM(n, mkni, y)； */
	ret = hi_sec_pke_modmulti(tmp->mkni, tmp->y, n, keylen, tmp->ms);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 17.软件配置模乘s=MM(n, ms, 1)流程结束。ms * 1 mod n */
	ret = hi_sec_pke_modmulti(tmp->ms, tmp->one, n, keylen, tmp->upper_s);
	hi_pke_systrace(ret, 0, 0, 0, 0);
	return ret;
}

hi_int32 hi_sec_ecdsa_sign(struct hi_sec_ecdsa_req *req)
{
	struct hi_ecdsa_oval_param_ptr_s oval_param;
	hi_int32 ret;
	hi_uint32 len, keylen;
	struct hi_ecdsa_sign_vari_tmp_s tmp;
	hi_uchar8 *lower_e = HI_NULL;
	struct hi_sec_ecdsa_req req_origin;

	hi_ecdsa_req_trans(req, &req_origin);
	ret = hi_ecdsa_sign_param_init(req, &oval_param, &keylen);
	if (ret != HI_RET_SUCC) { /* 若不成功已做 free md 处理 */
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	len = req->key_len;

	ret = hi_ecdsa_sign_tmp_init(&tmp, keylen);
	if (ret != HI_RET_SUCC) {
		hi_sec_pke_data_pading_free(&req->m, len);
		hi_sec_pke_data_pading_free(&req->d, len);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	ret = hi_ecdsa_sign_step1to4(&oval_param, &tmp, req, keylen);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret; /* 若不成功 step1to4 中已经做 free 处理 */
	}

	/* 5.软件调用HASH计算 ；H=HASH(M) */
	/* 6.软件做如下判断并产生e：记n的位宽为len_n，
	 * 如果len_n大于等于H的位宽则e=H，否则e取H的低len_n位 */
	/* 输入的m要算过hash, 长度为len */
	lower_e = req->m;

	/* 7.软件配置基本模N=2^(2len_n) mod n */
	ret = hi_ecdsa_sign_calc_uppern_mod(&oval_param, &tmp, keylen);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		goto hi_ecdsa_sign_free_k_n_md;
	}

	/* N取低位结果 */
	tmp.upper_n = tmp.upper_n + tmp.two_len_n - keylen;

	/* 8.软件配置模加E= e+0 mod n */
	ret = hi_sec_pke_modadd(lower_e, tmp.zero, oval_param.n,
		keylen, tmp.upper_e);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		goto hi_ecdsa_sign_free_k_n_md;
	}

	ret = hi_ecdsa_sign_step9to17(&tmp, req, oval_param.n, keylen);
	if (ret == HI_RET_SUCC) /* 输出s, 去除高位的pad 0 */
		hi_memcpy(req->sy, (tmp.upper_s + keylen - len), len);

hi_ecdsa_sign_free_k_n_md:
	hi_sec_pke_data_pading_free(&tmp.k, len);
	hi_free(tmp.n_576_data);
	tmp.n_576_data = HI_NULL;

	if (len != keylen) {
		hi_memmove(req_origin.d, (req->d + keylen - len), len);
		hi_memmove(req_origin.m, (req->m + keylen - len), len);
	}
	hi_sec_pke_data_pading_free(&req->d, len);
	hi_sec_pke_data_pading_free(&req->m, len);

	hi_ecdsa_req_trans(&req_origin, req);
	hi_pke_systrace(ret, 0, 0, 0, 0);
	return ret;
}

static hi_int32 hi_ecdsa_verify_param_init(
	struct hi_sec_ecdsa_req *req,
	struct hi_ecdsa_oval_param_ptr_s *oval_param, hi_uint32 *keylen)
{
	hi_int32 ret;
	hi_uint32 len = req->key_len;

	ret = hi_sec_pke_ecdsa_param_get(len, oval_param); /* 获取椭圆参数 */
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	ret = hi_sec_pke_data_pading(&req->m, len, keylen);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	ret = hi_sec_pke_data_pading(&req->qx, len, keylen);
	if (ret != HI_RET_SUCC) {
		hi_sec_pke_data_pading_free(&req->m, len);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	ret = hi_sec_pke_data_pading(&req->qy, len, keylen);
	if (ret != HI_RET_SUCC) {
		hi_sec_pke_data_pading_free(&req->m, len);
		hi_sec_pke_data_pading_free(&req->qx, len);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	ret = hi_sec_pke_data_pading(&req->sx, len, keylen);
	if (ret != HI_RET_SUCC) {
		hi_sec_pke_data_pading_free(&req->m, len);
		hi_sec_pke_data_pading_free(&req->qx, len);
		hi_sec_pke_data_pading_free(&req->qy, len);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	ret = hi_sec_pke_data_pading(&req->sy, len, keylen);
	if (ret != HI_RET_SUCC) {
		hi_sec_pke_data_pading_free(&req->m, len);
		hi_sec_pke_data_pading_free(&req->qx, len);
		hi_sec_pke_data_pading_free(&req->qy, len);
		hi_sec_pke_data_pading_free(&req->sx, len);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	hi_pke_systrace(ret, 0, 0, 0, 0);
	return ret;
}

static hi_int32 hi_ecdsa_verify_chk_req(struct hi_sec_ecdsa_req *req)
{
	if (req == HI_NULL || req->m == HI_NULL || 
		req->qx == HI_NULL || req->qy == HI_NULL ||
		req->sx == HI_NULL || req->sy == HI_NULL) {
		hi_pke_systrace(HI_RET_NULLPTR, 0, 0, 0, 0);
		return HI_RET_NULLPTR;
	}

	return HI_RET_SUCC;
}

static hi_void hi_ecdsa_pading_free_req_n576(
	struct hi_sec_ecdsa_req *req, hi_uchar8 *n_576_data)
{
	hi_uint32 len = req->key_len;

	hi_sec_pke_data_pading_free(&req->m, len);
	hi_sec_pke_data_pading_free(&req->qx, len);
	hi_sec_pke_data_pading_free(&req->qy, len);
	hi_sec_pke_data_pading_free(&req->sx, len);
	hi_sec_pke_data_pading_free(&req->sy, len);

	if (n_576_data != HI_NULL) {
		hi_free(n_576_data);
		n_576_data = HI_NULL;
	}

	return;
}

static hi_int32 hi_ecdsa_verify_step1(
	struct hi_sec_ecdsa_req *req, hi_uchar8 *n, hi_uint32 keylen)
{
	
	if (hi_sec_pke_data_valid(req->sx, n, 1, keylen) == HI_FALSE) {
		hi_ecdsa_pading_free_req_n576(req, HI_NULL);
		hi_pke_systrace(HI_RET_INVALID_PARA, 0, 0, 0, 0);
		return HI_RET_INVALID_PARA;
	}

	if (hi_sec_pke_data_valid(req->sy, n, 1, keylen) == HI_FALSE) {
		hi_ecdsa_pading_free_req_n576(req, HI_NULL);
		hi_pke_systrace(HI_RET_INVALID_PARA, 0, 0, 0, 0);
		return HI_RET_INVALID_PARA;
	}

	return HI_RET_SUCC;
}

static hi_int32 hi_ecdsa_verify_tmp_init(
	struct hi_sec_ecdsa_req *req,
	struct hi_ecdsa_verify_formula_s *tmp, hi_uint32 keylen)
{
	tmp->two_len_n = keylen * 2 + 8;
	tmp->datalen = keylen * 18  + tmp->two_len_n * 3;

	tmp->n_576_data = (hi_uchar8 *)hi_malloc(tmp->datalen);
	if (tmp->n_576_data == HI_NULL) {
		hi_ecdsa_pading_free_req_n576(req, HI_NULL);
		hi_pke_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
		return HI_RET_MALLOC_FAIL;
	}
	hi_memset(tmp->n_576_data, 0, tmp->datalen);

	tmp->two_two_len_n = tmp->n_576_data + tmp->two_len_n;
	tmp->upper_n = tmp->two_two_len_n + tmp->two_len_n;
	tmp->ms = tmp->upper_n + tmp->two_len_n;

	tmp->msni = tmp->ms + keylen;
	tmp->upper_e = tmp->msni + keylen;
	tmp->m_upper_e = tmp->upper_e + keylen;

	tmp->mu1 = tmp->m_upper_e + keylen;
	tmp->u1 = tmp->mu1 + keylen;
	tmp->mr = tmp->u1 + keylen;

	tmp->mu2 = tmp->mr + keylen;
	tmp->u2 = tmp->mu2 + keylen;

	tmp->u1gx = tmp->u2 + keylen;
	tmp->u1gy = tmp->u1gx + keylen;
	tmp->u2qx = tmp->u1gy + keylen;
	tmp->u2qy = tmp->u2qx + keylen;	

	tmp->rx = tmp->u2qy + keylen;
	tmp->ry = tmp->rx + keylen;

	tmp->v = tmp->ry + keylen;
	tmp->zero = tmp->v + keylen;
	tmp->one = tmp->zero + keylen;
	
	tmp->upper_s = tmp->upper_e + keylen;

	tmp->one[keylen - 1] = 0x1;

	return HI_RET_SUCC;
}

static hi_int32 hi_ecdsa_verify_calc_uppern_mod(
	struct hi_ecdsa_oval_param_ptr_s *oval,
	struct hi_ecdsa_verify_formula_s *tmp,
	hi_uint32 keylen)
{
	hi_int32 ret;
	hi_uchar8 *n_576_buf = HI_NULL;
	hi_uchar8 *a = HI_NULL;
	hi_uchar8 *p = HI_NULL;

	n_576_buf = tmp->n_576_data + tmp->two_len_n - keylen;

	hi_memcpy(n_576_buf, oval->n, keylen);
	tmp->two_two_len_n[tmp->two_len_n - keylen * 2 - 1] = 0x1;

	/* 公式 N = (2^(2len_n)) mod n */
	a = tmp->two_two_len_n; /* 赋值 a = (2^(2len_n)) */
	p = tmp->n_576_data;    /* 赋值 p = n_576_data */

	/* 计算c = a mod p */
	ret = hi_sec_pke_mod(a, p, tmp->two_len_n, tmp->upper_n);
	return ret;
}

static hi_int32 hi_ecdsa_verify_step5to6(
	struct hi_ecdsa_verify_formula_s *tmp, struct hi_sec_ecdsa_req *req,
	hi_uchar8 *n, hi_uint32 keylen)
{
	hi_int32 ret;

	/* 5.软件配置模乘ms=MM(n, s, N)；//注：模乘函数MM对应5.7.3节的模乘ms = s * N mod n，下同 */
	ret = hi_sec_pke_modmulti(req->sy, tmp->upper_n, n, keylen, tmp->ms);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_pading_free_req_n576(req, tmp->n_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;	
	}

	/* 6.软件配置模逆msni=ms-1 mod n； */
	ret = hi_sec_pke_modinvers(tmp->ms, n, keylen, tmp->msni);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_pading_free_req_n576(req, tmp->n_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;	
	}

	return ret;
}

static hi_int32 hi_ecdsa_verify_step8to13(
	struct hi_ecdsa_verify_formula_s *tmp, struct hi_sec_ecdsa_req *req,
	hi_uchar8 *n, hi_uint32 keylen)
{
	hi_int32 ret;

	/* 8.软件配置模乘mE=MM(n, E, N) */
	ret = hi_sec_pke_modmulti(tmp->upper_e, tmp->upper_n, n,
		keylen, tmp->m_upper_e);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_pading_free_req_n576(req, tmp->n_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;	
	}

	/* 9.软件配置模乘mu1=MM(n, mE, msni)； */
	ret = hi_sec_pke_modmulti(tmp->m_upper_e, tmp->msni, n,
		keylen, tmp->mu1);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_pading_free_req_n576(req, tmp->n_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;	
	}

	/* 10.软件配置模乘u1=MM(n, mu1, 1)； */
	ret = hi_sec_pke_modmulti(tmp->mu1, tmp->one, n, keylen, tmp->u1);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_pading_free_req_n576(req, tmp->n_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;	
	}

	/* 11.软件配置模乘mr=MM(n, r, N)； */
	ret = hi_sec_pke_modmulti(req->sx, tmp->upper_n, n, keylen, tmp->mr);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_pading_free_req_n576(req, tmp->n_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;	
	}

	/* 12.软件配置模乘mu2=MM(n, mr, msni)； */
	ret = hi_sec_pke_modmulti(tmp->mr, tmp->msni, n, keylen, tmp->mu2);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_pading_free_req_n576(req, tmp->n_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;	
	}

	/* 13.软件配置模乘u2=MM(n, mu2, 1)； */
	ret = hi_sec_pke_modmulti(tmp->mu2, tmp->one, n, keylen, tmp->u2);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_pading_free_req_n576(req, tmp->n_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;	
	}

	return ret;
}

static hi_int32 hi_ecdsa_verify_ecc_pm_u1g(
	struct hi_ecdsa_verify_formula_s *tmp,
	struct hi_ecdsa_oval_param_ptr_s *oval, hi_uint32 keylen)
{
	hi_int32 ret;
	struct hi_pke_ecc_pointmulti_s pm;

	pm.k = tmp->u1;

	pm.p = oval->p;
	pm.n = oval->n;
	pm.a = oval->a;
	pm.b = oval->b;
	pm.gx = oval->gx;
	pm.gy = oval->gy;
	pm.px = oval->gx;
	pm.py = oval->gy;
	pm.len = keylen;

	pm.rx = tmp->u1gx;
	pm.ry = tmp->u1gy;

	ret = hi_sec_pke_ecc_pointmulti(&pm);

	return ret;
}


static hi_int32 hi_ecdsa_verify_ecc_pm_u2q(
	struct hi_ecdsa_verify_formula_s *tmp,
	struct hi_ecdsa_oval_param_ptr_s *oval, hi_uint32 keylen,
	struct hi_sec_ecdsa_req *req)
{
	hi_int32 ret;
	struct hi_pke_ecc_pointmulti_s pm;

	pm.k = tmp->u2;

	pm.p = oval->p;
	pm.n = oval->n;
	pm.a = oval->a;
	pm.b = oval->b;
	pm.gx = oval->gx;
	pm.gy = oval->gy;

	pm.px = req->qx;
	pm.py = req->qy;

	pm.len = keylen;
	pm.rx = tmp->u2qx;
	pm.ry = tmp->u2qy;

	ret = hi_sec_pke_ecc_pointmulti(&pm);

	return ret;
}

static hi_int32 hi_ecdsa_verify_pointadd_r(
	struct hi_ecdsa_verify_formula_s *tmp,
	struct hi_ecdsa_oval_param_ptr_s *oval, hi_uint32 keylen)
{
	hi_int32 ret;
	struct hi_pke_pointadd_s padd;

	padd.sx  = tmp->u1gx;
	padd.sy  = tmp->u1gy;
	padd.rx  = tmp->u2qx;
	padd.ry  = tmp->u2qy;

	padd.p   = oval->p;
	padd.a   = oval->a;

	padd.len = keylen;
	padd.cx  = tmp->rx;
	padd.cy  = tmp->ry;

	ret = hi_sec_pke_pointadd(&padd);

	return ret;
}

static hi_int32 hi_ecdsa_verify_step14to17(
	struct hi_ecdsa_verify_formula_s *tmp, struct hi_sec_ecdsa_req *req,
	struct hi_ecdsa_oval_param_ptr_s *oval, hi_uint32 keylen)
{
	hi_int32 ret;


	/* 14.软件配置点乘u1G=u1*G */
	ret = hi_ecdsa_verify_ecc_pm_u1g(tmp, oval, keylen);
	if (ret) {
		hi_ecdsa_pading_free_req_n576(req, tmp->n_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 15.软件配置点乘u2Q=u2*Qu */
	ret = hi_ecdsa_verify_ecc_pm_u2q(tmp, oval, keylen, req);
	if (ret) {
		hi_ecdsa_pading_free_req_n576(req, tmp->n_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 16.软件配置点加R=u1G+u2Q */
	ret = hi_ecdsa_verify_pointadd_r(tmp, oval, keylen);
	if (ret) {
		hi_ecdsa_pading_free_req_n576(req, tmp->n_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 17.调用模加v= (xR+0) mod n */
	ret = hi_sec_pke_modadd(tmp->rx, tmp->zero, oval->n, keylen, tmp->v);
	if (ret) {
		hi_ecdsa_pading_free_req_n576(req, tmp->n_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	return ret;
}

static hi_void hi_ecdsa_verify_req_memmove(struct hi_sec_ecdsa_req *req_dst,
	struct hi_sec_ecdsa_req *req_src,  hi_uint32 keylen)
{
	hi_uint32 len = req_dst->key_len;

	if (len == keylen)
		return;

	hi_memmove(req_dst->m, (req_src->m + keylen - len), len);
	hi_memmove(req_dst->qx, (req_src->qx + keylen - len), len);
	hi_memmove(req_dst->qy, (req_src->qy + keylen - len), len);
	hi_memmove(req_dst->sx, (req_src->qx + keylen - len), len);
	hi_memmove(req_dst->sy, (req_src->qy + keylen - len), len);
	return;
}

/*
 * ECDSA验签. 算法位宽,有效224/256/384/521bit, 即28/32/48/66(高位补齐)bytes
 * S = (r, s) = (req->sx, req->sy)
 */
hi_int32 hi_sec_ecdsa_verify(struct hi_sec_ecdsa_req *req)
{
	hi_int32 ret;
	hi_uint32 keylen;
	struct hi_ecdsa_oval_param_ptr_s oval_param;
	struct hi_ecdsa_verify_formula_s tmp;
	hi_uchar8 *lower_e = HI_NULL;
	struct hi_sec_ecdsa_req req_origin;

	hi_ecdsa_req_trans(req, &req_origin);
	if (hi_ecdsa_verify_chk_req(req))
		return HI_RET_NULLPTR;

	ret = hi_ecdsa_verify_param_init(req, &oval_param, &keylen);
	if (ret != HI_RET_SUCC) { /* 若不成功已做 free md 处理 */
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 1.软件判断 r,s ?[1,n-1]，如果不满足则直接返回验签失败，流程结束 */
	ret = hi_ecdsa_verify_step1(req, oval_param.n, keylen);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}
	/* 2.软件调用HASH计算 H=HSAH(M)； */
	/* 3.软件做如下判断并产生e：记n的位宽为len_n，如果len_n大于等于H的位宽则e=H，否则e取H的低len_n位 */
	/* 输入的m要算过hash, 长度为len */
	lower_e = req->m;

	ret = hi_ecdsa_verify_tmp_init(req, &tmp, keylen);
	if (ret != HI_RET_SUCC)
		return ret;
	/*
	* 4.软件配置基本模N=22len_n mod n；
	* 注：如果len_n小于256则统一按照256位宽处理，下同；基本模的长度需按位宽大者的长度进行配置，不足则高位补零；
	*/
	ret = hi_ecdsa_verify_calc_uppern_mod(&oval_param, &tmp, keylen);
	if (ret) {
		hi_ecdsa_pading_free_req_n576(req, tmp.n_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* N取低位结果 */
	tmp.upper_n = tmp.upper_n + tmp.two_len_n - keylen;

	ret = hi_ecdsa_verify_step5to6(&tmp, req, oval_param.n, keylen);
	if (ret != HI_RET_SUCC)
		return ret;

	/* 7.软件配置模加E= e+0 mod n； */
	ret = hi_sec_pke_modadd(lower_e, tmp.zero, oval_param.n,
		keylen, tmp.upper_e);
	if (ret) {
		hi_ecdsa_pading_free_req_n576(req, tmp.n_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	ret = hi_ecdsa_verify_step8to13(&tmp, req, oval_param.n, keylen);
	if (ret != HI_RET_SUCC)
		return ret;

	ret = hi_ecdsa_verify_step14to17(&tmp, req, &oval_param, keylen);
	if (ret != HI_RET_SUCC)
		return ret;

	/* 18.软件判断v是否等于r，如果相等，则返回验签成功，否则返回验签失败 */
	if (hi_memcmp(tmp.v, req->sx, keylen) != 0)
		ret = HI_RET_FAIL;

	hi_ecdsa_verify_req_memmove(&req_origin, req, keylen);
	hi_ecdsa_pading_free_req_n576(req, tmp.n_576_data);
	hi_ecdsa_req_trans(&req_origin, req);

	hi_pke_systrace(ret, 0, 0, 0, 0);
	return ret;
}

/* 计算 Q = d * G */
static hi_int32 hi_ecdsa_keygen_pm_calc_qxy(
	struct hi_ecdsa_oval_param_ptr_s *oval,
	struct hi_sec_ecdsa_req *req, hi_uint32 keylen)
{
	hi_int32 ret;
	struct hi_pke_ecc_pointmulti_s pm;
	hi_uchar8 *qx_buf = HI_NULL;
	hi_uchar8 *qy_buf = HI_NULL;
	hi_uint32 len = req->key_len; /* len 为传入的原始len */

	/* 并把 d 对齐 */

	qx_buf = hi_malloc(keylen * 2);
	if (qx_buf == HI_NULL) {
		hi_sec_pke_data_pading_free(&req->d, len);
		hi_pke_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
		return HI_RET_MALLOC_FAIL;
	}
	qy_buf = qx_buf + keylen;

	pm.k = req->d; /* d */

	pm.p = oval->p;
	pm.n = oval->n;
	pm.a = oval->a;
	pm.b = oval->b;
	pm.gx = oval->gx;
	pm.gy = oval->gy;
	pm.px = oval->gx;
	pm.py = oval->gy;
	pm.len = keylen;

	pm.rx = qx_buf;
	pm.ry = qy_buf;

	ret = hi_sec_pke_ecc_pointmulti(&pm);
	if (ret != HI_RET_SUCC) {
		hi_free(qx_buf);
		qx_buf = HI_NULL;
		hi_sec_pke_data_pading_free(&req->d, len);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 输出Qx,Qy. 去除高位pad 0 */
	hi_memcpy(req->qx, (qx_buf + keylen - len), len);
	hi_memcpy(req->qy, (qy_buf + keylen - len), len);

	hi_free(qx_buf);
	qx_buf = HI_NULL;

	hi_pke_systrace(HI_RET_SUCC, 0, 0, 0, 0);
	return HI_RET_SUCC;
}

/* ECDSA密钥生成 算法位宽,有效224/256/384/521bit, 即28/32/48/66(高位补齐)Byte */
hi_int32 hi_sec_ecdsa_keygen(struct hi_sec_ecdsa_req *req)
{
	hi_int32 ret;
	struct hi_ecdsa_oval_param_ptr_s oval_param;
	hi_uint32 len;
	hi_uint32 keylen;
	hi_uchar8 *n_data = HI_NULL;
	struct hi_sec_ecdsa_req req_origin;

	if (req == HI_NULL || req->d == HI_NULL ||
		req->qx == HI_NULL || req->qy == HI_NULL) {
		hi_pke_systrace(HI_RET_NULLPTR, 0, 0, 0, 0);
		return HI_RET_NULLPTR;
	}
	hi_ecdsa_req_trans(req, &req_origin);

	len = req->key_len; /* len 为传入的原始len */

	ret = hi_sec_pke_ecdsa_param_get(len, &oval_param); /* 获取椭圆参数 */
	if (HI_RET_SUCC != ret) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}
	/* keylen 为处理后的长度 */
	if (len == HI_SEC_PKE_ECDSA_192BIT || len == HI_SEC_PKE_ECDSA_224BIT)
		keylen = HI_SEC_PKE_ECDSA_256BIT;
	else if (len == HI_SEC_PKE_ECDSA_521BIT)
		keylen = HI_SEC_PKE_ECDSA_576BIT;
	else
		keylen = len;

	n_data = oval_param.n + keylen - len; /* 不需要n高位补的0 */

	/* 1.产生随机数d∈[1,n-1] */
	ret = hi_sec_pke_random_get(n_data, len, req->d);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	ret = hi_sec_pke_data_pading(&req->d, len, &keylen);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 2. 计算 Q = d * G */
	ret = hi_ecdsa_keygen_pm_calc_qxy(&oval_param, req, keylen);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	if (len != keylen)
		hi_memmove(req_origin.d, (req->d + keylen - len), len);

	hi_sec_pke_data_pading_free(&req->d, len);
	hi_ecdsa_req_trans(&req_origin, req);

	hi_pke_systrace(ret, 0, 0, 0, 0);
	return ret;
}


static hi_void hi_ecdsa_keychk_free_q_p576(
	struct hi_sec_ecdsa_req *req, hi_uchar8 *p_576_data)
{
	hi_uint32 len = req->key_len;

	hi_sec_pke_data_pading_free(&req->qx, len);
	hi_sec_pke_data_pading_free(&req->qy, len);

	if (p_576_data != HI_NULL) {
		hi_free(p_576_data);
	}

	return;
}

static hi_int32 hi_ecdsa_keychk_step1to2(
	struct hi_sec_ecdsa_req *req, hi_uchar8 *p, hi_uint32 keylen)
{
	if (hi_sec_pke_data_valid(req->qx, p, 1, keylen) == HI_FALSE) {
		hi_ecdsa_keychk_free_q_p576(req, HI_NULL);
		hi_pke_systrace(HI_RET_INVALID_PARA, 0, 0, 0, 0);
		return HI_RET_INVALID_PARA;
	}
//
	if (hi_sec_pke_data_valid(req->qy, p, 1, keylen) == HI_FALSE) {
		hi_ecdsa_keychk_free_q_p576(req, HI_NULL);
		hi_pke_systrace(HI_RET_INVALID_PARA, 0, 0, 0, 0);
		return HI_RET_INVALID_PARA;
	}
//
	return HI_RET_SUCC;
}

static hi_int32 hi_ecdsa_keychk_param_init(
	struct hi_sec_ecdsa_req *req,
	struct hi_ecdsa_oval_param_ptr_s *oval_param, hi_uint32 *keylen)
{
	hi_int32 ret;
	hi_uint32 len = req->key_len;

	ret = hi_sec_pke_ecdsa_param_get(len, oval_param); /* 获取椭圆参数 */
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	ret = hi_sec_pke_data_pading(&req->qx, len, keylen);
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	ret = hi_sec_pke_data_pading(&req->qy, len, keylen);
	if (ret != HI_RET_SUCC)
		hi_sec_pke_data_pading_free(&req->qx, len);

	hi_pke_systrace(ret, 0, 0, 0, 0);
	return ret;
}

static hi_int32 hi_ecdsa_keychk_tmp_init(
	struct hi_sec_ecdsa_req *req,
	struct hi_ecdsa_keychk_formula_s *tmp, hi_uint32 keylen)
{
	tmp->two_len_n = keylen * 2 + 8;
	tmp->datalen = keylen * 14  + tmp->two_len_n * 3;

	tmp->p_576_data = (hi_uchar8 *)hi_malloc(tmp->datalen);
	if (tmp->p_576_data == HI_NULL) {
		hi_ecdsa_keychk_free_q_p576(req, HI_NULL);
		hi_pke_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
		return HI_RET_MALLOC_FAIL;
	}
	hi_memset(tmp->p_576_data, 0, tmp->datalen);

	tmp->two_two_len_p = tmp->p_576_data + tmp->two_len_n;
	tmp->upper_p = tmp->two_two_len_p + tmp->two_len_n;
	tmp->mx = tmp->upper_p + tmp->two_len_n;

	tmp->my = tmp->mx + keylen;
	tmp->ma = tmp->my + keylen;
	tmp->mb = tmp->ma + keylen;

	tmp->mx2 = tmp->mb + keylen;
	tmp->mx3 = tmp->mx2 + keylen;
	tmp->max = tmp->mx3 + keylen;
	tmp->mx3p = tmp->max + keylen;

	tmp->m_upper_z = tmp->mx3p + keylen;
	tmp->my2 = tmp->m_upper_z + keylen;

	tmp->diff = tmp->my2 + keylen;

	tmp->zero = tmp->diff + keylen;
	tmp->rx = tmp->zero + keylen;
	tmp->ry = tmp->rx + keylen;

	return HI_RET_SUCC;
}

static hi_int32 hi_ecdsa_keychk_calc_upperp_mod(
	struct hi_ecdsa_oval_param_ptr_s *oval,
	struct hi_ecdsa_keychk_formula_s *tmp,
	hi_uint32 keylen)
{
	hi_int32 ret;
	hi_uchar8 *p_576_buf = HI_NULL;
	hi_uchar8 *a = HI_NULL;
	hi_uchar8 *p = HI_NULL;

	p_576_buf = tmp->p_576_data + tmp->two_len_n - keylen;

	hi_memcpy(p_576_buf, oval->p, keylen);
	tmp->two_two_len_p[tmp->two_len_n - keylen * 2 - 1] = 0x1;

	/* 公式 P=2^(2*np) mod p */
	a = tmp->two_two_len_p;
	p = tmp->p_576_data;
	/* 计算c = a mod p */
	ret = hi_sec_pke_mod(a, p, tmp->two_len_n, tmp->upper_p); 

	return ret;
}

static hi_int32 hi_ecdsa_keychk_step4to10(
	struct hi_ecdsa_keychk_formula_s *tmp, struct hi_sec_ecdsa_req *req,
	struct hi_ecdsa_oval_param_ptr_s *oval, hi_uint32 keylen)
{
	hi_int32 ret;
	hi_uchar8 *p = oval->p;

	/* 4.软件配置模乘mx = MM(p, Q.x, P)；//注：模乘公式对应 mx = Q.x * P mod p， 下同； */
	ret = hi_sec_pke_modmulti(req->qx, tmp->upper_p, p, keylen, tmp->mx);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_keychk_free_q_p576(req, tmp->p_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 5.软件配置模乘my = MM(p, Q.y, P)； */
	ret = hi_sec_pke_modmulti(req->qy, tmp->upper_p, p, keylen, tmp->my);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_keychk_free_q_p576(req, tmp->p_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 6.软件配置模乘ma = MM(p, a, P)； */
	ret = hi_sec_pke_modmulti(oval->a, tmp->upper_p, p, keylen, tmp->ma);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_keychk_free_q_p576(req, tmp->p_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 7.软件配置模乘mb = MM(p, b, P)； */
	ret = hi_sec_pke_modmulti(oval->b, tmp->upper_p, p, keylen, tmp->mb);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_keychk_free_q_p576(req, tmp->p_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 8.软件配置模乘mx2 = MM(p, mx, mx) */
	ret = hi_sec_pke_modmulti(tmp->mx, tmp->mx, p, keylen, tmp->mx2);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_keychk_free_q_p576(req, tmp->p_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 9.软件配置模乘mx3 = MM(p, mx2, mx) */
	ret = hi_sec_pke_modmulti(tmp->mx2, tmp->mx, p, keylen, tmp->mx3);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_keychk_free_q_p576(req, tmp->p_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 10.软件配置模乘max = MM(p, ma, mx) */
	ret = hi_sec_pke_modmulti(tmp->ma, tmp->mx, p, keylen, tmp->max);
	if (ret != HI_RET_SUCC)
		hi_ecdsa_keychk_free_q_p576(req, tmp->p_576_data);

	hi_pke_systrace(ret, 0, 0, 0, 0);
	return ret;

}

static hi_int32 hi_ecdsa_keychk_step11to15(
	struct hi_ecdsa_keychk_formula_s *tmp, struct hi_sec_ecdsa_req *req,
	hi_uchar8 *p, hi_uint32 keylen)
{
	hi_int32 ret;

	/* 11.软件配置模加mx3p = (mx3 + max) mod p */
	ret = hi_sec_pke_modadd(tmp->mx3, tmp->max, p, keylen, tmp->mx3p);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_keychk_free_q_p576(req, tmp->p_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 12.软件配置模加mZ = (mx3p + mb) mod p ； */
	ret = hi_sec_pke_modadd(tmp->mx3p, tmp->mb, p, keylen, tmp->m_upper_z);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_keychk_free_q_p576(req, tmp->p_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 13.软件配置模乘my2 = MM(p, my, my)； */
	ret = hi_sec_pke_modmulti(tmp->my, tmp->my, p, keylen, tmp->my2);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_keychk_free_q_p576(req, tmp->p_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 14.软件配置模减 diff = (my2 - mZ) mod p； */
	ret = hi_sec_pke_modminus(tmp->my2, tmp->m_upper_z, p,
		keylen, tmp->diff);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_keychk_free_q_p576(req, tmp->p_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 15.软件验证 diff 是否等于'0'，不等于零则返回Q无效，流程结束 */
	if (hi_memcmp(tmp->diff, tmp->zero, keylen) != 0) {
		hi_ecdsa_keychk_free_q_p576(req, tmp->p_576_data);
		ret = HI_RET_FAIL;
	}

	hi_pke_systrace(ret, 0, 0, 0, 0);
	return ret;
}

static hi_int32 hi_ecdsa_keychk_step16(
	struct hi_ecdsa_keychk_formula_s *tmp, struct hi_sec_ecdsa_req *req,
	struct hi_ecdsa_oval_param_ptr_s *oval, hi_uint32 keylen)
{
	hi_int32 ret;
	struct hi_pke_ecc_pointmulti_s pm;

	pm.k = oval->n;

	pm.p = oval->p;
	pm.n = oval->n;
	pm.a = oval->a;
	pm.b = oval->b;
	pm.gx = oval->gx;
	pm.gy = oval->gy;

	pm.px = req->qx;
	pm.py = req->qy;

	pm.len = keylen;

	pm.rx = tmp->rx;
	pm.ry = tmp->ry;

	ret = hi_sec_pke_ecc_pointmulti(&pm);

	return ret;
}

hi_int32 hi_sec_ecdsa_keychk(struct hi_sec_ecdsa_req *req)
{
	hi_int32 ret;
	hi_uint32 keylen;
	struct hi_ecdsa_keychk_formula_s tmp;
	struct hi_ecdsa_oval_param_ptr_s oval_param;
	struct hi_sec_ecdsa_req req_origin;

	if (req == HI_NULL || req->qx == HI_NULL || req->qy == HI_NULL) {
		hi_pke_systrace(HI_RET_NULLPTR, 0, 0, 0, 0);
		return HI_RET_NULLPTR;
	}
	hi_ecdsa_req_trans(req, &req_origin);

	ret = hi_ecdsa_keychk_param_init(req, &oval_param, &keylen);
	if (ret != HI_RET_SUCC) { /* 若不成功已做 free 处理 */
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 1.软件判断Q是否为无穷远点，是则返回Q无效，流程结束； */
	/* 2.软件验证0<=Q.x<p, 0<=Q.y<p，如果不满足则返回Q无效，流程结束； */
	ret = hi_ecdsa_keychk_step1to2(req, oval_param.p, keylen);
	if (ret != HI_RET_SUCC)
		return ret;

	ret = hi_ecdsa_keychk_tmp_init(req, &tmp, keylen);
	if (ret != HI_RET_SUCC)
		return ret;

	/*
	* 3.软件配置基本模P=2^(2*np) mod p；
	* 注：其中np为p的位宽，192、224统一按照256位宽，下同，
	* 基本模的长度需按位宽大者的长度进行配置，不足则高位补零；
	*/
	ret = hi_ecdsa_keychk_calc_upperp_mod(&oval_param, &tmp, keylen);
	if (ret != HI_RET_SUCC) {
		hi_ecdsa_keychk_free_q_p576(req, tmp.p_576_data);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* N取低位结果 */
	tmp.upper_p = tmp.upper_p + tmp.two_len_n - keylen;

	ret = hi_ecdsa_keychk_step4to10(&tmp, req, &oval_param, keylen);
	if (ret != HI_RET_SUCC)
		return ret;

	ret = hi_ecdsa_keychk_step11to15(&tmp, req, oval_param.p, keylen);
	if (ret != HI_RET_SUCC)
		return ret;

	ret = hi_ecdsa_keychk_step16(&tmp, req, &oval_param, keylen);
	if (ret != HI_SEC_PKE_FAILURE_FLAG_UNLIMIT_POINT)
		ret = HI_RET_FAIL;
	else
		ret = HI_RET_SUCC;
	
	hi_ecdsa_keychk_free_q_p576(req, tmp.p_576_data);
	hi_ecdsa_req_trans(&req_origin, req);

	hi_pke_systrace(ret, 0, 0, 0, 0);
	return ret;
}
