/**
 * @file   : hal_ecc.h
 * @brief  : ECC椭圆曲线算法对外接口API
 * @par    : Copyright(c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2017/12/22
 * @author : m00172947
 */
#ifndef __HAL_ECC_H__
#define __HAL_ECC_H__
#include <common_ecc.h>

/**
 * @brief 签名数据结构
 */
typedef struct hal_ecc_sign_struct {
	const ecc_curve_s    *pcurve_s;        /**< 椭圆曲线参数 */
	const hal_ecc_key_s  *pkey_s;          /**< 公/私钥对 */
	const u8             *phash;           /**< 哈希值 */
	u32                  hashlen;          /**< 哈希数据的字节长度 */
	u8                   *psignature;      /**< 输出签名数据 */
	u32                  *psignaturelen;   /**< 签名数据的字节长度 */
} hal_ecc_sign_s;

/**
 * @brief 验签的数据结构
 */
typedef struct hal_ecc_verify_struct {
	const ecc_curve_s    *pcurve_s;        /**< 椭圆曲线参数 */
	const hal_ecc_key_s  *pkey_s;          /**< 公/私钥对 */
	const u8             *phash;           /**< 哈希值 */
	u32                  hashlen;          /**< 哈希数据的字节长度 */
	u8                   *psignature;      /**< 签名数据 */
	u32                  signaturelen;     /**< 签名数据的字节长度 */
} hal_ecc_verify_s;

/**
 * @brief ECC密钥协商生成密钥的数据结构
 */
typedef struct hal_ecka_secret_struct {
	const ecc_curve_s   *pcurve_s;   /**< 椭圆曲线参数 */
	const hal_ecc_key_s *pkey_s;     /**< 密钥 */
	u8                  *psecret;    /**< 输出密钥 */
	u32                 *psecretlen; /**< 密钥长度 */
} hal_ecka_secret_s;

/**
 * @brief 密钥协商获取杂凑KEY值的接口
 */
typedef struct hal_ecka_derive_struct {
	const u8     *pz;          /**< z值数据 */
	u32          zlen;         /**< z值数据的字节长度 */
	const u8     *pinfo;       /**< 输入数据 */
	u32          infolen;      /**< info数据的字节指针 */
	u8           *poutkey;     /**< 输出杂凑的KEY值 */
	u32          *poutkeylen;  /**< 输出杂凑KEY值的字节长度 */
} hal_ecka_derive_s;

/**
 * @brief     : ECC生成公私钥对接口
 * @param[io]  : pkey_s    公/私钥对
 * @param[in]  : pcurve_s  ECC椭圆曲线参数
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_ecc_gen_key(const hal_ecc_key_s *pkey_s, const ecc_curve_s *pcurve_s);

/**
 * @brief      : ECC密钥协商ECKA接口
 * @param[io]  : pecka_secret_s    密钥协商参数(::hal_ecka_secret_s)，输出密钥
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_ecc_ecka_gen_secret(const hal_ecka_secret_s *psecret_s);

/**
 * @brief      : KA派生接口
 * @param[io]  : pderive_s   指向派生输入/输出参数(::hal_ecka_derive_s)的指针
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_ecc_ecka_derive(const hal_ecka_derive_s *pderive_s);

/**
 * @brief      : ECC签名接口(带HASH值签名)
 * @param[io]  : psign_s 签名数据参数，输出签名数据
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_ecc_sign(const hal_ecc_sign_s *psign_s);

/**
 * @brief      : ECC验签接口(对HASH值验签)
 * @param[in]  : pverify_s 验签数据参数
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_ecc_verify(const hal_ecc_verify_s *pverify_s);

#endif /* end of __HAL_ECC_H__ */
