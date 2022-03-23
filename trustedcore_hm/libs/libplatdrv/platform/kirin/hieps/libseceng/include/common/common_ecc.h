/**
 * @file   : common_ecc.h
 * @brief  : ECCȫ�ֹ�������/����
 * @par    : Copyright(c) 2018-2034, HUAWEI Technology Co., Ltd.
 * @date   : 2018/01/20
 * @author : m00172947
 */
#ifndef __COMMON_ECC_H__
#define __COMMON_ECC_H__
#include <common_def.h>

#define SM2_KEY_WIDTH           (ECC_KEYWIDTH_256)     /**< SM2����Կ��� */
#define SM2_KEY_LEN             (SM2_KEY_WIDTH >> 3)   /**< SM2����Կ����(Bytes) */
#define SM2_POINT_LEN           (SM2_KEY_LEN << 1)     /**< SM2��Բ���ߵ���ֽڳ��� */

/**
 * @brief ECC֧�ֵ�KEY���
 */
enum ecc_keywidth_e {
    ECC_KEYWIDTH_MIN = 128,
    ECC_KEYWIDTH_128 = 128,
    ECC_KEYWIDTH_160 = 160,
    ECC_KEYWIDTH_192 = 192,
    ECC_KEYWIDTH_224 = 224,
    ECC_KEYWIDTH_256 = 256,
};

/**
 * @brief ECC��Բ�����㷨����
 */
struct ecc_curve_s {
    const u8	*pp;	    /* ��ӦECC���߲���p */
    const u8	*pa;	    /* ��ӦECC���߲���a */
    const u8	*pb;	    /* ��ӦECC���߲���b */
    const u8	*pn;	    /* ��ӦECC���߲���n */
    const u8	*pgx;	    /* ��ӦECC���߲���gx */
    const u8	*pgy;	    /* ��ӦECC���߲���gy */
    /* const u8	 *ph;	 *< ��ӦECC���߲���h(������)��Ŀǰ�ò�������Ĭ��ֵ1 */
};

/**
 * @brief ��Բ������Կ
 */
struct hal_ecc_key_s {
    u32	width;	     /* �㷨��� */
    u8	*ppubx;     /* ָ��Կxֵ��ָ�룬�㷨����ֽ�����ȡ�� */
    u8	*ppuby;     /* ָ��Կyֵ��ָ�룬�㷨����ֽ�����ȡ�� */
    u8	*ppriv;     /* ָ��˽Կ��ָ�룬�㷨����ֽ�����ȡ�� */
};

#endif /* end of __COMMON_ECC_H__ */
