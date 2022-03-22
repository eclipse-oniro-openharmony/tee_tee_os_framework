/**
 * @file   : hal_sec.h
 * @brief  : common api provide to outside
 * @par    : Copyright (c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2018/09/20
 * @author : l00370476, liuchong13@huawei.com
 */
#ifndef __HAL_SEC_H__
#define __HAL_SEC_H__

/**
 * @brief      : hal_check_smx_support
 *               check smx supported
 * @param[in]  : smx_e: SMX_SM2, SMX_SM3, SMX_SM4
 * @return     : BSP_RET_OK represents support, others unsupport
 */
err_bsp_t hal_check_smx_support(u32 smx_e);

err_bsp_t hal_scramb_enable(u32 enable);

#endif
