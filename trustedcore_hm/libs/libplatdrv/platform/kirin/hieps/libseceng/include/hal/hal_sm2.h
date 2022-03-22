/**
 * @file   : hal_sm2.h
 * @brief  : 国密SM2对外接口API
 * @par    : Copyright(c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2017/12/21
 * @author : m00172947
 */
#ifndef __HAL_SM2_H__
#define __HAL_SM2_H__
#include <common_symm.h>
#include <common_ecc.h>

#define HAL_SM2_C1_HEAD                     (0x04)
#define HAL_SM2_C1_HEAD_LEN                 (1)
#define HAL_SM2_C1_LEN                      (SM2_POINT_LEN + HAL_SM2_C1_HEAD_LEN)
#define HAL_SM2_C3_LEN                      (SYMM_OUTLEN_SM3)
#define HAL_SM2_C_LEN(inlen)                (HAL_SM2_C1_LEN + (inlen) + HAL_SM2_C3_LEN)

/**
 * @brief 获取Z值的参数
 */
typedef struct hal_ecc_getz_struct {
	const hal_ecc_key_s *pkey_s; /**< 公/私钥对 */
	const u8            *pid;    /**< 输入的ID */
	u32                 idlen;   /**< 输入ID的字节长度 */
	u8                  *pz;     /**< 输出参数z */
	u32                 *pzlen;  /**< 参数z的字节长度 */
} hal_sm2_getz_s;

/**
 * @brief 加/解密参数
 */
typedef struct hal_sm2_crypto_struct {
	const hal_ecc_key_s     *pkey_s;    /**< 公/私钥对 */
	const u8                *pdin;      /**< 输入数据 */
	u32                     dinlen;     /**< 输入数据的字节长度 */
	u8                      *pdout;     /**< 输出结果 */
	u32                     *pdoutlen;  /**< 输出结果的字节长度 */
} hal_sm2_crypto_s;

/**
 * @brief 签名参数
 */
typedef struct hal_sm2_sign_struct {
	const hal_ecc_key_s *pkey_s;           /**< 公/私钥对 */
	const u8            *phash;            /**< 哈希数据 */
	u32                 hashlen;           /**< 哈希数据的字节长度 */
	u8                  *psignature;       /**< 签名数据 */
	u32                 *psignaturelen;    /**< 签名数据的缓存长度，输出字节长度 */
} hal_sm2_sign_s;

/**
 * @brief 验签参数
 */
typedef struct hal_sm2_verify_struct {
	const hal_ecc_key_s *pkey_s;           /**< 公/私钥对 */
	const u8            *phash;            /**< 哈希数据 */
	u32                 hashlen;           /**< 哈希数据的字节长度 */
	u8                  *psignature;       /**< 签名数据 */
	u32                 signaturelen;      /**< 签名数据的字节长度 */
} hal_sm2_verify_s;

/**
 * @brief 密钥交换操作中，自身的参数信息
 */
typedef struct hal_sm2_exchkey_self_struct {
	const u8                      *ppriv;       /**< 私钥 */
	const u8                      *pZ;          /**< Z值，可辨别标识、部分椭圆曲线系统参数和公钥的杂凑值 */
	u8                            *pr;          /**< 随机数r */
	u8                            *pRx;         /**< 生成点R的x值 */
	u8                            *pRy;         /**< 生成点R的y值 */
	u8                            *pUVx;        /**< 椭圆曲线点U/V的x值 */
	u8                            *pUVy;        /**< 椭圆曲线点U/V的y值 */
	u8                            *pS;          /**< <可选>杂凑校验值 */
	u8                            *pK;          /**< 生成的K值 */
	u32                           klen;         /**< K的长度 */
} hal_sm2_exchkey_self_s;

/**
 * @brief 密钥交换操作中，对方提供的参数信息
 */
typedef struct hal_sm2_exchkey_party_struct {
	const u8      *ppubx;  /**< 公钥曲线点的x值 */
	const u8      *ppuby;  /**< 公钥曲线点的y值 */
	const u8      *pRx;    /**< 曲线点R的x值 */
	const u8      *pRy;    /**< 曲线点R的y值 */
	const u8      *pZ;     /**< Z值，可辨别标识、部分椭圆曲线系统参数和公钥的杂凑值 */
	const u8      *pS;     /**< <可选>杂凑校验值 */
} hal_sm2_exchkey_party_s;

/**
 * @brief 秘要交换的角色
 */
typedef enum hal_sm2_exchkey_role_enum {
	SM2_EXCHKEY_ROLE_REQ, /**< 秘要交换的发起方A */
	SM2_EXCHKEY_ROLE_RSP, /**< 秘要交换的响应方B */
} hal_sm2_exchkey_role_e;

/**
 * @brief      : 获取国密SM2椭圆曲线参数A
 * @param[in]  : pbuf    指向输出缓冲区
 * @param[in]  : poutlen 指向缓冲区长度的指针，输出实际参数长度
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_getA(u8 *pbuf, u32 *poutlen);

/**
 * @brief      : 获取国密SM2椭圆曲线参数B
 * @param[in]  : pbuf    指向输出缓冲区
 * @param[in]  : poutlen 指向缓冲区长度的指针，输出实际参数长度
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_getB(u8 *pbuf, u32 *poutlen);

/**
 * @brief      : 获取国密SM2椭圆曲线参数G
 * @param[in]  : pbuf    指向输出缓冲区
 * @param[in]  : poutlen 指向缓冲区长度的指针，输出实际参数长度
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_getG(u8 *pbuf, u32 *poutlen);

/**
 * @brief      : SM2获取Z值接口
 * @param[io]  : pgetz_s   获取Z值的参数
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_getZ(const hal_sm2_getz_s *pgetz_s);

/**
 * @brief      : SM2生成公私钥对接口
 * @param[io]  : pkey_s 公/私钥对
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_gen_key(hal_ecc_key_s *pkey_s);

/**
 * @brief      : 国密SM2加密运算
 * @param[io]  : pcrypto_s   加密参数，参见::hal_sm2_crypto_s
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_encrypt(const hal_sm2_crypto_s *pcrypto_s);

/**
 * @brief      : 国密SM2解密运算
 * @param[io]  : pcrypto_s   解密参数，参见::hal_sm2_crypto_s
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_decrypt(const hal_sm2_crypto_s *pcrypto_s);

/**
 * @brief      : SM2签名接口
 * @param[io]  : psign_s   签名参数，参见::hal_sm2_sign_s
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_sign(const hal_sm2_sign_s *psign_s);

/**
 * @brief      : SM2验签接口
 * @param[io]  : pverify_s   验签参数，参见::hal_sm2_verify_s
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_verify(const hal_sm2_verify_s *pverify_s);

/**
 * @brief      : SM2密钥交换精简流程(不含rR生成)
 * @param[in]  : role_e     密钥交换角色
 * @param[io]  : pself_s    自身参数
 * @param[in]  : pparty_s   对方参数
 * @param[out] : pS2        <可选>校验值S2
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_exchkey_simple(hal_sm2_exchkey_role_e role_e
				, hal_sm2_exchkey_self_s * pself_s, hal_sm2_exchkey_party_s * pparty_s);

#endif /* end of __HAL_SM2_H__ */
