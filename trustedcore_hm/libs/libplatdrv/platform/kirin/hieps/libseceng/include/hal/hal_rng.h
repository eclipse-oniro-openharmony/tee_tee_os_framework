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

#define HAL_RNG_MAXLEN      (32768) /* 一次可获取的最大字节长度 */

/**
 * @brief      : 生成真随机数
 * @param[out]  : ptrnd 输出缓存
 * @param[in]  : len 随机数字节长度
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_rng_gen_trnd(u8 *ptrnd, u32 len);

/**
 * @brief      : 生成伪随机数
 * @param[out]  : pprnd 输出缓存
 * @param[in]  : len 随机数字节长度
 * @return     : ::err_bsp_t
 */
err_bsp_t hal_rng_gen_prnd(u8 *pprnd, u32 len);

#endif /* end of _HAL_RNG_H_ */
