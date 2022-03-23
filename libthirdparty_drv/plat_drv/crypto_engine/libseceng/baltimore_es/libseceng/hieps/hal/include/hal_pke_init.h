/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: PKE init
 * Author     : h00401342
 * Create     : 2019/08/19
 * Note       :
 */
#ifndef __HAL_PKE_INIT_H__
#define __HAL_PKE_INIT_H__
#include <pal_types.h>

/**
 * @brief      : rsa ip init hal need traverse all rsa
 */
err_bsp_t hal_rsa_init(void);

/**
 * @brief      : ecc ip init hal need traverse all rsa
 */
err_bsp_t hal_ecc_init(void);

err_bsp_t hal_sm9_init(void);


#endif /* end of __HAL_PKE_INIT_H__ */
