/**
 * @file   : hal_sm2.h
 * @brief  : ����SM2����ӿ�API
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
 * @brief ��ȡZֵ�Ĳ���
 */
typedef struct hal_ecc_getz_struct {
	const hal_ecc_key_s *pkey_s; /**< ��/˽Կ�� */
	const u8            *pid;    /**< �����ID */
	u32                 idlen;   /**< ����ID���ֽڳ��� */
	u8                  *pz;     /**< �������z */
	u32                 *pzlen;  /**< ����z���ֽڳ��� */
} hal_sm2_getz_s;

/**
 * @brief ��/���ܲ���
 */
typedef struct hal_sm2_crypto_struct {
	const hal_ecc_key_s     *pkey_s;    /**< ��/˽Կ�� */
	const u8                *pdin;      /**< �������� */
	u32                     dinlen;     /**< �������ݵ��ֽڳ��� */
	u8                      *pdout;     /**< ������ */
	u32                     *pdoutlen;  /**< ���������ֽڳ��� */
} hal_sm2_crypto_s;

/**
 * @brief ǩ������
 */
typedef struct hal_sm2_sign_struct {
	const hal_ecc_key_s *pkey_s;           /**< ��/˽Կ�� */
	const u8            *phash;            /**< ��ϣ���� */
	u32                 hashlen;           /**< ��ϣ���ݵ��ֽڳ��� */
	u8                  *psignature;       /**< ǩ������ */
	u32                 *psignaturelen;    /**< ǩ�����ݵĻ��泤�ȣ�����ֽڳ��� */
} hal_sm2_sign_s;

/**
 * @brief ��ǩ����
 */
typedef struct hal_sm2_verify_struct {
	const hal_ecc_key_s *pkey_s;           /**< ��/˽Կ�� */
	const u8            *phash;            /**< ��ϣ���� */
	u32                 hashlen;           /**< ��ϣ���ݵ��ֽڳ��� */
	u8                  *psignature;       /**< ǩ������ */
	u32                 signaturelen;      /**< ǩ�����ݵ��ֽڳ��� */
} hal_sm2_verify_s;

/**
 * @brief ��Կ���������У�����Ĳ�����Ϣ
 */
typedef struct hal_sm2_exchkey_self_struct {
	const u8                      *ppriv;       /**< ˽Կ */
	const u8                      *pZ;          /**< Zֵ���ɱ���ʶ��������Բ����ϵͳ�����͹�Կ���Ӵ�ֵ */
	u8                            *pr;          /**< �����r */
	u8                            *pRx;         /**< ���ɵ�R��xֵ */
	u8                            *pRy;         /**< ���ɵ�R��yֵ */
	u8                            *pUVx;        /**< ��Բ���ߵ�U/V��xֵ */
	u8                            *pUVy;        /**< ��Բ���ߵ�U/V��yֵ */
	u8                            *pS;          /**< <��ѡ>�Ӵ�У��ֵ */
	u8                            *pK;          /**< ���ɵ�Kֵ */
	u32                           klen;         /**< K�ĳ��� */
} hal_sm2_exchkey_self_s;

/**
 * @brief ��Կ���������У��Է��ṩ�Ĳ�����Ϣ
 */
typedef struct hal_sm2_exchkey_party_struct {
	const u8      *ppubx;  /**< ��Կ���ߵ��xֵ */
	const u8      *ppuby;  /**< ��Կ���ߵ��yֵ */
	const u8      *pRx;    /**< ���ߵ�R��xֵ */
	const u8      *pRy;    /**< ���ߵ�R��yֵ */
	const u8      *pZ;     /**< Zֵ���ɱ���ʶ��������Բ����ϵͳ�����͹�Կ���Ӵ�ֵ */
	const u8      *pS;     /**< <��ѡ>�Ӵ�У��ֵ */
} hal_sm2_exchkey_party_s;

/**
 * @brief ��Ҫ�����Ľ�ɫ
 */
typedef enum hal_sm2_exchkey_role_enum {
	SM2_EXCHKEY_ROLE_REQ, /**< ��Ҫ�����ķ���A */
	SM2_EXCHKEY_ROLE_RSP, /**< ��Ҫ��������Ӧ��B */
} hal_sm2_exchkey_role_e;

/**
 * @brief      : ��ȡ����SM2��Բ���߲���A
 * @param[in]  : pbuf    ָ�����������
 * @param[in]  : poutlen ָ�򻺳������ȵ�ָ�룬���ʵ�ʲ�������
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_getA(u8 *pbuf, u32 *poutlen);

/**
 * @brief      : ��ȡ����SM2��Բ���߲���B
 * @param[in]  : pbuf    ָ�����������
 * @param[in]  : poutlen ָ�򻺳������ȵ�ָ�룬���ʵ�ʲ�������
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_getB(u8 *pbuf, u32 *poutlen);

/**
 * @brief      : ��ȡ����SM2��Բ���߲���G
 * @param[in]  : pbuf    ָ�����������
 * @param[in]  : poutlen ָ�򻺳������ȵ�ָ�룬���ʵ�ʲ�������
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_getG(u8 *pbuf, u32 *poutlen);

/**
 * @brief      : SM2��ȡZֵ�ӿ�
 * @param[io]  : pgetz_s   ��ȡZֵ�Ĳ���
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_getZ(const hal_sm2_getz_s *pgetz_s);

/**
 * @brief      : SM2���ɹ�˽Կ�Խӿ�
 * @param[io]  : pkey_s ��/˽Կ��
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_gen_key(hal_ecc_key_s *pkey_s);

/**
 * @brief      : ����SM2��������
 * @param[io]  : pcrypto_s   ���ܲ������μ�::hal_sm2_crypto_s
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_encrypt(const hal_sm2_crypto_s *pcrypto_s);

/**
 * @brief      : ����SM2��������
 * @param[io]  : pcrypto_s   ���ܲ������μ�::hal_sm2_crypto_s
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_decrypt(const hal_sm2_crypto_s *pcrypto_s);

/**
 * @brief      : SM2ǩ���ӿ�
 * @param[io]  : psign_s   ǩ���������μ�::hal_sm2_sign_s
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_sign(const hal_sm2_sign_s *psign_s);

/**
 * @brief      : SM2��ǩ�ӿ�
 * @param[io]  : pverify_s   ��ǩ�������μ�::hal_sm2_verify_s
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_verify(const hal_sm2_verify_s *pverify_s);

/**
 * @brief      : SM2��Կ������������(����rR����)
 * @param[in]  : role_e     ��Կ������ɫ
 * @param[io]  : pself_s    �������
 * @param[in]  : pparty_s   �Է�����
 * @param[out] : pS2        <��ѡ>У��ֵS2
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_sm2_exchkey_simple(hal_sm2_exchkey_role_e role_e
				, hal_sm2_exchkey_self_s * pself_s, hal_sm2_exchkey_party_s * pparty_s);

#endif /* end of __HAL_SM2_H__ */
