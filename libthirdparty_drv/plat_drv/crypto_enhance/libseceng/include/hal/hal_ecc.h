/**
 * @file   : hal_ecc.h
 * @brief  : ECC��Բ�����㷨����ӿ�API
 * @par    : Copyright(c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2017/12/22
 * @author : m00172947
 */
#ifndef __HAL_ECC_H__
#define __HAL_ECC_H__
#include <common_ecc.h>

/**
 * @brief ǩ�����ݽṹ
 */
typedef struct hal_ecc_sign_struct {
	const ecc_curve_s    *pcurve_s;        /**< ��Բ���߲��� */
	const hal_ecc_key_s  *pkey_s;          /**< ��/˽Կ�� */
	const u8             *phash;           /**< ��ϣֵ */
	u32                  hashlen;          /**< ��ϣ���ݵ��ֽڳ��� */
	u8                   *psignature;      /**< ���ǩ������ */
	u32                  *psignaturelen;   /**< ǩ�����ݵ��ֽڳ��� */
} hal_ecc_sign_s;

/**
 * @brief ��ǩ�����ݽṹ
 */
typedef struct hal_ecc_verify_struct {
	const ecc_curve_s    *pcurve_s;        /**< ��Բ���߲��� */
	const hal_ecc_key_s  *pkey_s;          /**< ��/˽Կ�� */
	const u8             *phash;           /**< ��ϣֵ */
	u32                  hashlen;          /**< ��ϣ���ݵ��ֽڳ��� */
	u8                   *psignature;      /**< ǩ������ */
	u32                  signaturelen;     /**< ǩ�����ݵ��ֽڳ��� */
} hal_ecc_verify_s;

/**
 * @brief ECC��ԿЭ��������Կ�����ݽṹ
 */
typedef struct hal_ecka_secret_struct {
	const ecc_curve_s   *pcurve_s;   /**< ��Բ���߲��� */
	const hal_ecc_key_s *pkey_s;     /**< ��Կ */
	u8                  *psecret;    /**< �����Կ */
	u32                 *psecretlen; /**< ��Կ���� */
} hal_ecka_secret_s;

/**
 * @brief ��ԿЭ�̻�ȡ�Ӵ�KEYֵ�Ľӿ�
 */
typedef struct hal_ecka_derive_struct {
	const u8     *pz;          /**< zֵ���� */
	u32          zlen;         /**< zֵ���ݵ��ֽڳ��� */
	const u8     *pinfo;       /**< �������� */
	u32          infolen;      /**< info���ݵ��ֽ�ָ�� */
	u8           *poutkey;     /**< ����Ӵյ�KEYֵ */
	u32          *poutkeylen;  /**< ����Ӵ�KEYֵ���ֽڳ��� */
} hal_ecka_derive_s;

/**
 * @brief     : ECC���ɹ�˽Կ�Խӿ�
 * @param[io]  : pkey_s    ��/˽Կ��
 * @param[in]  : pcurve_s  ECC��Բ���߲���
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_ecc_gen_key(const hal_ecc_key_s *pkey_s, const ecc_curve_s *pcurve_s);

/**
 * @brief      : ECC��ԿЭ��ECKA�ӿ�
 * @param[io]  : pecka_secret_s    ��ԿЭ�̲���(::hal_ecka_secret_s)�������Կ
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_ecc_ecka_gen_secret(const hal_ecka_secret_s *psecret_s);

/**
 * @brief      : KA�����ӿ�
 * @param[io]  : pderive_s   ָ����������/�������(::hal_ecka_derive_s)��ָ��
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_ecc_ecka_derive(const hal_ecka_derive_s *pderive_s);

/**
 * @brief      : ECCǩ���ӿ�(��HASHֵǩ��)
 * @param[io]  : psign_s ǩ�����ݲ��������ǩ������
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_ecc_sign(const hal_ecc_sign_s *psign_s);

/**
 * @brief      : ECC��ǩ�ӿ�(��HASHֵ��ǩ)
 * @param[in]  : pverify_s ��ǩ���ݲ���
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_ecc_verify(const hal_ecc_verify_s *pverify_s);

#endif /* end of __HAL_ECC_H__ */
