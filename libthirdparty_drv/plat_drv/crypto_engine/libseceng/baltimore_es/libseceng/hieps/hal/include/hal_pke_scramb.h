/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description:  pke scramb for hardware
 * Author     : h00401342
 * Create     : 2018/02/24
 * Note       :
 */
#ifndef __HAL_PKE_SCRAMB_H__
#define __HAL_PKE_SCRAMB_H__
#include <common_pke.h>

/**
 * @brief      : PKE scramb control
 * @param[in]  : enable  SEC_ENABLE SEC_DISABLE
 * @note       :
 */
err_bsp_t hal_scramb_enable(u32 enable);

/**
 * @brief      : sramb preprocess(OnChipRom scramb clear)
 * @return     : void
 * @note       : in onChipRom enable scramb probablely
 *             : so need to preprocess
 */
err_bsp_t hal_scramb_preprocess(void);

/**
 * @brief      : scramb init
 * @return     : void
 */
err_bsp_t hal_scramb_init(void);

#endif /* end of __HAL_PKE_SCRAMB_H__ */
