/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: msp tee se ext api tlv header file
 * Author     : z00387284
 * Create     : 2020/01/11
 */

#ifndef __MSP_TEE_SE_EXT_API_TLV_H__
#define __MSP_TEE_SE_EXT_API_TLV_H__
#include "msp_tee_se_ext_api.h"
#include "tee_defines.h"
#include "tee_internal_api.h"
#include <stdint.h>

#define EXT_APDU_HEADER_LEN 0x7
/* 30 is used for the TPDU info */
#define MAX_EXT_APDU_DATA_LEN (32 * 1024 - 30)
#define MAX_STD_APDU_DATA_LEN 0xFF
#define APDU_RES_MIN_LENGTH 2

#define TEE_TIME_LEN 8
#define IMAGE_SIZE_LEN 4
#define NVM_DATA_SIZE_LEN 4
#define USER_ID_LEN 1
#define SA_VERSION_LEN 4

#define apdu_field(data_len)                                                                                           \
    struct {                                                                                                           \
        uint8_t tag;                                                                                                   \
        uint8_t len;                                                                                                   \
        uint8_t data[data_len];                                                                                        \
    }

#define APDU_HEADER                                                                                                    \
    uint8_t cla;                                                                                                       \
    uint8_t ins;                                                                                                       \
    uint8_t p1;                                                                                                        \
    uint8_t p2;                                                                                                        \
    uint8_t lc;

/* apdu msg struct: install for load */
struct apdu_install_for_load {
    APDU_HEADER

    apdu_field(SA_AID_LEN) sa_aid;
    apdu_field(TEE_TIME_LEN) tee_time;
    apdu_field(IMAGE_SIZE_LEN) image_size;
    uint8_t le;
};

/* apdu msg struct: install for install */
struct apdu_install_for_install {
    APDU_HEADER

    apdu_field(SA_AID_LEN) sa_aid;
    apdu_field(SA_INSTANCE_ID_LEN) sa_instance_id;
    apdu_field(TEE_TIME_LEN) tee_time;
    apdu_field(NVM_DATA_SIZE_LEN) nvm_data_size;
    apdu_field(SA_VERSION_LEN) version;
    apdu_field(USER_ID_LEN) user_id;
    uint8_t le;
};

/* apdu msg struct: get_status_private */
struct apdu_get_status_private {
    APDU_HEADER

    apdu_field(SA_AID_LEN) sa_aid;
    uint8_t le;
};

/* apdu msg struct: install for install */
struct command_info_load_sa {
    uint32_t command_len;
    uint32_t apdu_header_len;
    uint32_t left_len;
    uint32_t data_len;
    uint8_t block_cnt;
    uint32_t image_offset;
};

/*
 * @brief         : set the apdu command of loading sa
 * @param[out]    : command, the command buffer
 * @param[inout]  : info, the sending info of the sa image
 * @param[in]     : sa_image, the address of the sa image data
 * @return        : TEE_Result
 */
TEE_Result msp_tee_se_set_load_command_apdu(uint8_t *command, struct command_info_load_sa *info,
                                            const uint8_t *sa_image);
/*
 * @brief      : set the apdu command of install_for_load
 * @param[out] : command, the apdu command buffer of install_for_load
 * @param[in]  : sa_aid, the sa aid
 * @param[in]  : sa_aid_len, the length of the sa aid
 * @param[in]  : image_size, the size of the sa image
 * @return     : TEE_Result
 */
TEE_Result msp_tee_se_set_install_for_load(struct apdu_install_for_load *command, const uint8_t *sa_aid,
                                           uint32_t sa_aid_len, uint32_t image_size);

/*
 * @brief      : set the apdu command of install_for_install
 * @param[out] : command, the apdu command buffer of install_for_install
 * @param[in]  : install_sa_info, the info about installing sa
 * @return     : TEE_Result
 */
TEE_Result msp_tee_se_set_install_for_install(struct apdu_install_for_install *command,
                                              const struct msp_install_sa_info *install_sa_info);

/*
 * @brief      : get sa status form the apdu response
 * @param[in]  : response, the response of apdu command
 * @param[in]  : response_len, the length of the response
 * @param[out] : status, the sa status
 * @return     : TEE_Result
 */
TEE_Result msp_tee_se_get_sa_status_from_apdu_repsonse(const uint8_t *response, uint32_t response_len,
                                                       struct sa_status_detail *status);

/*
 * @brief      : set the apdu command of get sa status privately
 * @param[out] : command, the response of apdu command
 * @param[in]  : sa_aid, the sa aid
 * @param[in]  : sa_aid_len, the length of sa aid
 * @return     : TEE_Result
 */
TEE_Result msp_tee_se_set_get_sa_status(struct apdu_get_status_private *command, const uint8_t *sa_aid,
                                        uint32_t sa_aid_len);
#endif /* __MSP_TEE_SE_EXT_API_TLV_H__ */
