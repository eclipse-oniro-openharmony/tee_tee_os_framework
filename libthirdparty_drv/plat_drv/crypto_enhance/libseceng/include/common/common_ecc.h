/**
 * @file   : common_ecc.h
 * @brief  : ECC全局共享数据/类型
 * @par    : Copyright(c) 2018-2034, HUAWEI Technology Co., Ltd.
 * @date   : 2018/01/20
 * @author : m00172947
 */
#ifndef __COMMON_ECC_H__
#define __COMMON_ECC_H__
#include <common_def.h>

#define SM2_KEY_WIDTH           (ECC_KEYWIDTH_256)     /**< SM2的密钥宽度 */
#define SM2_KEY_LEN             (SM2_KEY_WIDTH >> 3)   /**< SM2的密钥长度(Bytes) */
#define SM2_POINT_LEN           (SM2_KEY_LEN << 1)     /**< SM2椭圆曲线点的字节长度 */

/**
 * @brief ECC支持的KEY宽度
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
 * @brief ECC椭圆曲线算法参数
 */
struct ecc_curve_s {
    const u8	*pp;	    /* 对应ECC曲线参数p */
    const u8	*pa;	    /* 对应ECC曲线参数a */
    const u8	*pb;	    /* 对应ECC曲线参数b */
    const u8	*pn;	    /* 对应ECC曲线参数n */
    const u8	*pgx;	    /* 对应ECC曲线参数gx */
    const u8	*pgy;	    /* 对应ECC曲线参数gy */
    /* const u8	 *ph;	 *< 对应ECC曲线参数h(余因子)，目前该参数采用默认值1 */
};

/**
 * @brief 椭圆曲线密钥
 */
struct hal_ecc_key_s {
    u32	width;	     /* 算法宽度 */
    u8	*ppubx;     /* 指向公钥x值的指针，算法宽度字节向上取整 */
    u8	*ppuby;     /* 指向公钥y值的指针，算法宽度字节向上取整 */
    u8	*ppriv;     /* 指向私钥的指针，算法宽度字节向上取整 */
};

#endif /* end of __COMMON_ECC_H__ */
