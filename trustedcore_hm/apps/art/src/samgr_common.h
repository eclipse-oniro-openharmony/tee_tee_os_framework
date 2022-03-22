/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: sa mananger common header file.
 * Author: x00225909
 * Create: 2020-07-21
 */
#ifndef __SAMGR_COMMON_H__
#define __SAMGR_COMMON_H__

#include "msp_tee_se_ext_api.h"
#include "tee_internal_api.h"

/*
 * @brief      : sa mgr load sa
 * @param[in]  : sa_image, the sa image
 * @param[in]  : sa_image_len, the length of the sa image
 * @param[in]  : sa_aid, the sa aid
 * @param[in]  : sa_aid_len, the length of the sa aid
 * @return     : TEE_Result
 */
TEE_Result sa_mgr_load_sa(const uint8_t *sa_image, uint32_t sa_image_len, const uint8_t *sa_aid, uint32_t sa_aid_len);

/*
 * @brief      : sa mgr get sa status
 * @param[in]  : sa_aid, the sa aid
 * @param[in]  : sa_aid_len, the length of sa aid
 * @param[out] : status, the sa status, see the struct sa_status_detail
 * @return     : TEE_Result
 */
TEE_Result sa_mgr_get_sa_status(const uint8_t *sa_aid, uint32_t sa_aid_len, struct sa_status_detail *status);

/*
 * @brief      : sa mgr install sa
 * @param[in]  : install_sa_info, the info about installing sa, see the struct msp_install_sa_info
 * @param[out] : status, the sa status, see the struct sa_status
 * @return     : TEE_Result
 */
TEE_Result sa_mgr_install_sa(const struct msp_install_sa_info *install_sa_info, struct sa_status *status);

#endif /* __SAMGR_COMM_H__ */
