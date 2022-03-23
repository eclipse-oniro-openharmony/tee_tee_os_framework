/**
 * @file   : hal_rng.h
 * @brief  : random number generator functions
 * @par    : Copyright(c) 2018-2034, HUAWEI Technology Co., Ltd.
 * @date   : 2018/02/24
 * @author : h00418764
 */
#ifndef _HAL_RNG_H_
#define _HAL_RNG_H_
#include <common_def.h>

#define HAL_RNG_MAXLEN      (32768) /* һ�οɻ�ȡ������ֽڳ��� */

/**
 * @brief      : �����������
 * @param[out]  : ptrnd �������
 * @param[in]  : len ������ֽڳ���
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_rng_gen_trnd(u8 *ptrnd, u32 len);

/**
 * @brief      : ����α�����
 * @param[out]  : pprnd �������
 * @param[in]  : len ������ֽڳ���
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_rng_gen_prnd(u8 *pprnd, u32 len);

#endif /* end of _HAL_RNG_H_ */
