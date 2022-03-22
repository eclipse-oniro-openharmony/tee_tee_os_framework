/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: msp tee se ext api header file
 * Author     : z00387284
 * Create     : 2019/09/19
 */

#ifndef __MSP_TEE_SE_EXT_API_H__
#define __MSP_TEE_SE_EXT_API_H__
#include "tee_internal_api.h"

#define SA_AID_LEN 16
#define SA_INSTANCE_ID_LEN SA_AID_LEN
#define SA_INSTANCE_MAX_NUM_PER_SA 1

enum tee_ext_api_error_code_enum {
    TEE_ERROR_NEED_LOAD_SA = 0x89000001,
    TEE_ERROR_NVM_DATA_SIZE_DIFF = 0x89000002,
    TEE_ERROR_ALREADY_INSTALLED_SA = 0x89000003,
    TEE_ERROR_NEED_UPDATE_SA = 0x89000004,
};

/* note: must match with msp cos define */
enum sa_lcs_enum {
    SA_LCS_NO_LOAD = 0,
    SA_LCS_LOADED,
    SA_LCS_INSTALLED,
    SA_LFC_ENUM_BUTT
};

struct msp_install_sa_info {
    uint8_t sa_aid[SA_AID_LEN];
    uint8_t sa_instance_id[SA_INSTANCE_ID_LEN];
    uint32_t user_id;
    uint32_t nvm_data_size;
    uint32_t version;
};

struct sa_instance_status {
    uint8_t sa_instance_id[SA_INSTANCE_ID_LEN];
    uint32_t sa_select_status;
};

struct sa_status {
    uint32_t sa_version;
    uint16_t sa_lfc;
    uint16_t sa_instance_num;
    struct sa_instance_status instance_status[SA_INSTANCE_MAX_NUM_PER_SA];
};

struct sa_status_detail {
    uint32_t sa_version;
    uint32_t sa_size;
    uint16_t sa_lfc;
    uint16_t sa_instance_num;
    struct sa_instance_status instance_status[SA_INSTANCE_MAX_NUM_PER_SA];
};

/*
 * @brief      : the tee ext api-------load sa
 * @param[in]  : sa_image, the sa image
 * @param[in]  : sa_image_len, the length of the sa image
 * @param[in]  : sa_aid, the sa aid
 * @param[in]  : sa_aid_len, the length of the sa aid
 * @return     : TEE_Result
 */
TEE_Result TEE_EXT_MSPLoadSA(const uint8_t *sa_image, uint32_t sa_image_len,
                             const uint8_t *sa_aid, uint32_t sa_aid_len);

/*
 * @brief      : the tee ext api-------install sa
 * @param[in]  : install_sa_info, the info about installing sa, see the struct msp_install_sa_info
 * @param[out] : status, the sa status, see the struct sa_status
 * @return     : TEE_Result
 */
TEE_Result TEE_EXT_MSPInstallSA(const struct msp_install_sa_info *install_sa_info, struct sa_status *status);

/*
 * @brief      : the tee ext api-------get sa status
 * @param[in]  : sa_aid, the sa aid
 * @param[in]  : sa_aid_len, the length of sa aid
 * @param[out] : status, the sa status, see the struct sa_status_detail
 * @return     : TEE_Result
 */
TEE_Result TEE_EXT_MSPGetStatus(const uint8_t *sa_aid, uint32_t sa_aid_len, struct sa_status_detail *status);

#endif /* __MSP_TEE_SE_EXT_API_H__ */
