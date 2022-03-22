/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: msp tee se ext api tlv c file
 * Author: z00387284
 * Create: 2019-10-21
 */
#include "msp_tee_se_ext_api_tlv.h"
#include "msp_tee_tlv.h"
#include "hisee_try_catch.h"
#include "securec.h"
#include "msp_tee_se_ext_api.h"
#include <tee_internal_se_api.h>
#include "tee_time_api.h"

#define CLA_CMD 0x80

#define INS_LOAD 0xE8
#define LAST_COMAMND 0x80
#define MORE_COMMAND 0x00

#define INS_INSTALL 0xE6
#define P1_INSTALL_FOR_LOAD 0x02
#define P2_INSTALL_FOR_LOAD 0x01
#define P1_INSTALL_FOR_INSTALL 0x04
#define P2_INSTALL_FOR_INSTALL 0x01
#define P1_GET_STATUS 0x00
#define P2_GET_STATUS 0x00

#define INS_GET_STATUS_PRIVATE 0xF3

#define DATA_4BYTE  0x4
#define DATA_3BYTE  0x3
#define DATA_2BYTE  0x2
#define LENGTH_1BYTE_MASK 0x7F
#define STD_APDU_HEADER_LEN 5

#define APDU_EXT_HEADER_LC_LEN 3

#define APDU_LE_LEN 1

#define APDU_SW_LEN APDU_RES_MIN_LENGTH

#define BITS_MASK 0xFF

#define ARRARY_0_INDEX  0
#define ARRARY_1_INDEX  1
#define ARRARY_2_INDEX  2

enum apdu_tag {
    APDU_SA_AID_TAG = 0,
    APDU_SA_INSTANCE_ID_TAG = 1,
    APDU_TEE_TIME_TAG = 2,
    APDU_SA_IMAGE_SIZE_TAG = 3,
    APDU_SA_VERSION_TAG = 4,
    APDU_NVM_DATA_SIZE_TAG = 5,
    APDU_USER_ID_TAG = 6,
    APDU_SA_LFC_TAG = 7,
    APDU_SA_INSTANCE_NUM_TAG = 8,
    APDU_SA_INSTANCE_SELECT_STATUS_TAG = 9,

    APDU_CIPHERED_LOAD_FILE_DATA_BLOCK_TAG = 0xD4,

    APDU_SA_STATUS_TAG = 0x2A,
    APDU_SA_INSTANCE_STATUS_TAG = 0x2B,
};

static void msp_fill_tee_time(TEE_Time *tee_time)
{
    TEE_GetSystemTime(tee_time);
    msp_set_hton(tee_time->seconds);
    msp_set_hton(tee_time->millis);
}

/*
 * @brief      : set the apdu command of install_for_load
 * @param[out] : command, the apdu command buffer of install_for_load
 * @param[in]  : sa_aid, the sa aid
 * @param[in]  : sa_aid_len, the length of the sa aid
 * @param[in]  : image_size, the size of the sa image
 * @return     : TEE_Result
 */
TEE_Result msp_tee_se_set_install_for_load(struct apdu_install_for_load *command, const uint8_t *sa_aid,
                                           uint32_t sa_aid_len, uint32_t image_size)
{
    TEE_Result result;
    TEE_Time tee_time;
    uint32_t len;

    __TRY
    {
        throw_if_null(command, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(sa_aid, TEE_ERROR_BAD_PARAMETERS);
        throw_if(sa_aid_len != SA_AID_LEN, TEE_ERROR_BAD_PARAMETERS);

        /*
         * CLA: 0x80
         * INS: 0xE6
         * P1: 0x02 GP2.2.1 page160 table 11-41
         * P2: 0x01 GP2.2.1 page161
         * Lc: 0x19
         * DATA:
         * length of SA ID 1 byte
         * SA ID 16 bytes
         * TEE time 8 bytes
         * Le 0x00
         */
        command->cla = CLA_CMD;
        command->ins = INS_INSTALL;
        command->p1 = P1_INSTALL_FOR_LOAD;
        command->p2 = P2_INSTALL_FOR_LOAD;
        command->lc = sizeof(*command) - STD_APDU_HEADER_LEN - APDU_LE_LEN;

        /* add sa_aid */
        len = sizeof(command->sa_aid);
        result = msp_set_tlv(&command->sa_aid, &len, APDU_SA_AID_TAG, sa_aid_len, (const uint8_t *)sa_aid);
        throw_if(result != TEE_SUCCESS, result);
        throw_if(len != sizeof(command->sa_aid), TEE_ERROR_GENERIC);

        /* add tee time */
        msp_fill_tee_time(&tee_time);
        len = sizeof(command->tee_time);
        result = msp_set_tlv(&command->tee_time, &len, APDU_TEE_TIME_TAG, sizeof(tee_time), (const uint8_t *)&tee_time);
        throw_if(result != TEE_SUCCESS, result);
        throw_if(len != sizeof(command->tee_time), TEE_ERROR_GENERIC);

        /* add sa image size */
        len = sizeof(command->image_size);
        result = msp_set_tlv_u32(&command->image_size, &len, APDU_SA_IMAGE_SIZE_TAG, image_size);
        throw_if(result != TEE_SUCCESS, result);
        throw_if(len != sizeof(command->image_size), TEE_ERROR_GENERIC);

        /* add Le, 0x00 means the response can be any length */
        command->le = 0x00;
        return TEE_SUCCESS;
    }
    __CATCH
    {
        return ERR_CODE;
    }
}
#define MAX_CIPHER_LOAD_FILE_DATA_BLOCK_TAG_SIZE 1
#define MAX_EXT_CIPHER_LOAD_FILE_DATA_BLOCK_LEN_SIZE 3
#define MAX_EXT_CIPHER_LOAD_FILE_DATA_BLOCK_LEN                                                                        \
    (MAX_EXT_APDU_DATA_LEN - MAX_CIPHER_LOAD_FILE_DATA_BLOCK_TAG_SIZE - MAX_EXT_CIPHER_LOAD_FILE_DATA_BLOCK_LEN_SIZE)

/* apdu msg struct: load sa msg header */
struct apdu_load_header {
    uint8_t cla;
    uint8_t ins;
    uint8_t p1; /* is last block */
    uint8_t p2; /* block sn */
    uint8_t lc[APDU_EXT_HEADER_LC_LEN];

    uint8_t data[1];
};

static void msp_set_load_apdu(struct command_info_load_sa *info, struct apdu_load_header *header)
{
    /*
     * CLA: 0x80
     * INS: 0xE8
     * P1: 0x02 GP2.2.1 page71 table 11-56
     * P2: 0x01 GP2.2.1 page161
     * Lc: 0x11
     * DATA:
     * length of SA ID 1 byte
     * SA ID 16 bytes
     * Le 0x00
     */
    header->cla = CLA_CMD;
    header->ins = INS_LOAD;
    if (info->left_len >= MAX_EXT_CIPHER_LOAD_FILE_DATA_BLOCK_LEN) {
        info->left_len -= MAX_EXT_CIPHER_LOAD_FILE_DATA_BLOCK_LEN;
        info->data_len = MAX_EXT_CIPHER_LOAD_FILE_DATA_BLOCK_LEN;
        if (info->left_len == 0)
            header->p1 = LAST_COMAMND;
        else
            header->p1 = MORE_COMMAND;
        header->lc[ARRARY_0_INDEX] = 0x00;
        header->lc[ARRARY_1_INDEX] = (MAX_EXT_APDU_DATA_LEN >> BITS_OF_BYTE) & BITS_MASK;
        header->lc[ARRARY_2_INDEX] = MAX_EXT_APDU_DATA_LEN & BITS_MASK;
        info->apdu_header_len = EXT_APDU_HEADER_LEN;
    } else if (info->left_len > MAX_STD_APDU_DATA_LEN) {
        info->data_len = info->left_len;
        info->left_len = 0;
        header->p1 = LAST_COMAMND;
        header->lc[ARRARY_0_INDEX] = 0x00;
        header->lc[ARRARY_1_INDEX] = ((info->data_len + DATA_4BYTE) >> BITS_OF_BYTE) & BITS_MASK;
        header->lc[ARRARY_2_INDEX] = (info->data_len + DATA_4BYTE) & BITS_MASK;
        info->apdu_header_len = EXT_APDU_HEADER_LEN;
    } else if (info->left_len > MAX_STD_APDU_DATA_LEN - DATA_3BYTE) {
        info->data_len = info->left_len;
        info->left_len = 0;
        header->p1 = LAST_COMAMND;
        header->lc[ARRARY_0_INDEX] = 0x00;
        header->lc[ARRARY_1_INDEX] = ((info->data_len + DATA_3BYTE) >> BITS_OF_BYTE) & BITS_MASK;
        header->lc[ARRARY_2_INDEX] = (info->data_len + DATA_3BYTE) & BITS_MASK;
        info->apdu_header_len = EXT_APDU_HEADER_LEN;
    } else if (info->left_len > LENGTH_1BYTE_MASK) {
        info->data_len = info->left_len;
        info->left_len = 0;
        header->p1 = LAST_COMAMND;
        header->lc[ARRARY_0_INDEX] = info->data_len + DATA_3BYTE;
        info->apdu_header_len = STD_APDU_HEADER_LEN;
    } else {
        info->data_len = info->left_len;
        info->left_len = 0;
        header->p1 = LAST_COMAMND;
        header->lc[0] = info->data_len + DATA_2BYTE;
        info->apdu_header_len = STD_APDU_HEADER_LEN;
    }

    header->p2 = info->block_cnt;
    info->block_cnt++;
}

/*
 * @brief      : set the apdu command of loading sa
 * @param[out] : command, the command buffer
 * @param[inout]  : info, the sending info of the sa image
 * @param[in] : sa_image, the address of the sa image data
 * @return     : TEE_Result
 */
TEE_Result msp_tee_se_set_load_command_apdu(uint8_t *command, struct command_info_load_sa *info,
                                            const uint8_t *sa_image)
{
    struct apdu_load_header *header;
    header = (struct apdu_load_header *)command;
    uint32_t len;
    uint32_t result;

    __TRY
    {
        throw_if_null(command, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(info, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(sa_image, TEE_ERROR_BAD_PARAMETERS);

        msp_set_load_apdu(info, header);

        len = MAX_EXT_APDU_DATA_LEN;
        result = msp_set_tlv(command + info->apdu_header_len, &len, APDU_CIPHERED_LOAD_FILE_DATA_BLOCK_TAG,
                             info->data_len, (const uint8_t *)sa_image + info->image_offset);
        throw_if(result != TEE_SUCCESS, result);

        info->image_offset += info->data_len;

        /* Le is 0x00 */
        command[info->apdu_header_len + len] = 0x00;
        /* header length + data length + le length */
        info->command_len = info->apdu_header_len + len + 1;

        return TEE_SUCCESS;
    }
    __CATCH
    {
        return ERR_CODE;
    }
}

/*
 * @brief      : set the apdu command of install_for_install
 * @param[out] : command, the apdu command buffer of install_for_install
 * @param[in]  : install_sa_info, the info about installing sa
 * @return     : TEE_Result
 */
TEE_Result msp_tee_se_set_install_for_install(struct apdu_install_for_install *command,
                                              const struct msp_install_sa_info *install_sa_info)
{
    TEE_Result result;
    TEE_Time tee_time;
    uint32_t len;

    __TRY
    {
        throw_if_null(command, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(install_sa_info, TEE_ERROR_BAD_PARAMETERS);
        /* CLA: 0x80
         * INS: 0xE6
         * P1: 0x04 GP2.2.1 page160 table 11-41
         * P2: 0x01 GP2.2.1 page161
         * Lc: 0x19
         * DATA: see struct apdu_install_for_install
         * Le 0x00
         */
        /* add apdu command header */
        command->cla = CLA_CMD;
        command->ins = INS_INSTALL;
        command->p1 = P1_INSTALL_FOR_INSTALL;
        command->p2 = P2_INSTALL_FOR_INSTALL;
        command->lc = sizeof(*command) - STD_APDU_HEADER_LEN - APDU_LE_LEN;

        /* add sa_aid */
        len = sizeof(command->sa_aid);
        result =
            msp_set_tlv(&command->sa_aid, &len, APDU_SA_AID_TAG, SA_AID_LEN, (const uint8_t *)install_sa_info->sa_aid);
        throw_if(result != TEE_SUCCESS, result);
        throw_if(len != sizeof(command->sa_aid), TEE_ERROR_GENERIC);

        /* add instance id */
        len = sizeof(command->sa_instance_id);
        result = msp_set_tlv(&command->sa_instance_id, &len, APDU_SA_INSTANCE_ID_TAG, SA_INSTANCE_ID_LEN,
                             (const uint8_t *)install_sa_info->sa_instance_id);
        throw_if(result != TEE_SUCCESS, result);
        throw_if(len != sizeof(command->sa_instance_id), TEE_ERROR_GENERIC);

        /* add tee time */
        msp_fill_tee_time(&tee_time);
        len = sizeof(command->tee_time);
        result = msp_set_tlv(&command->tee_time, &len, APDU_TEE_TIME_TAG, sizeof(tee_time), (const uint8_t *)&tee_time);
        throw_if(result != TEE_SUCCESS, result);
        throw_if(len != sizeof(command->tee_time), TEE_ERROR_GENERIC);

        /* add nvm data size */
        len = sizeof(command->nvm_data_size);
        result = msp_set_tlv_u32(&command->nvm_data_size, &len, APDU_NVM_DATA_SIZE_TAG, install_sa_info->nvm_data_size);
        throw_if(result != TEE_SUCCESS, result);
        throw_if(len != sizeof(command->nvm_data_size), TEE_ERROR_GENERIC);

        /* add version */
        len = sizeof(command->version);
        result = msp_set_tlv_u32(&command->version, &len, APDU_SA_VERSION_TAG, install_sa_info->version);
        throw_if(result != TEE_SUCCESS, result);
        throw_if(len != sizeof(command->version), TEE_ERROR_GENERIC);

        /* add user id */
        len = sizeof(command->user_id);
        result = msp_set_tlv_u8(&command->user_id, &len, APDU_USER_ID_TAG, install_sa_info->user_id);
        throw_if(result != TEE_SUCCESS, result);
        throw_if(len != sizeof(command->user_id), TEE_ERROR_GENERIC);

        /* add le */
        command->le = 0x00;
        return TEE_SUCCESS;
    }
    __CATCH
    {
        return ERR_CODE;
    }
}

struct sa_tlv_de_sa_status {
    uint32_t instance_count;
    uint32_t stop_rcv_sa_instance_status_flg;
    struct msp_tlv_de_data sa_status;
    struct msp_tlv_de_data sa_lfc;
    struct msp_tlv_de_data sa_version;
    struct msp_tlv_de_data sa_size;
    struct msp_tlv_de_data sa_instance_num;
    struct msp_tlv_de_data sa_instantce_status[SA_INSTANCE_MAX_NUM_PER_SA];
    struct msp_tlv_de_data instance_id[SA_INSTANCE_MAX_NUM_PER_SA];
    struct msp_tlv_de_data sa_select_status[SA_INSTANCE_MAX_NUM_PER_SA];
};

struct sa_de_sa_status_para {
    struct sa_tlv_de_sa_status tlv_status;
    struct msp_tlv_de_data tlv;
    uint32_t data_len;
    uint32_t offset;
    uint32_t len;
    bool is_struct;
    bool stop_rcv_sa_instance_status_flg;
    uint32_t instance_count;
};

static TEE_Result msp_tee_se_de_sa_status(uint32_t tag, uint32_t len, const uint8_t *value, void *tlv_stru,
                                          uint32_t tlv_stru_len)
{
    struct sa_tlv_de_sa_status *tlv_status = (struct sa_tlv_de_sa_status *)tlv_stru;

    __TRY
    {
        throw_if_null(tlv_stru, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(value, TEE_ERROR_BAD_PARAMETERS);
        throw_if(tlv_stru_len < sizeof(struct sa_tlv_de_sa_status), TEE_ERROR_BAD_PARAMETERS);

        switch (tag) {
            case APDU_SA_LFC_TAG:
                msp_tee_tlv_save(tag, len, value, &tlv_status->sa_lfc);
                break;
            case APDU_SA_VERSION_TAG:
                msp_tee_tlv_save(tag, len, value, &tlv_status->sa_version);
                break;
            case APDU_SA_IMAGE_SIZE_TAG:
                msp_tee_tlv_save(tag, len, value, &tlv_status->sa_size);
                break;
            case APDU_SA_INSTANCE_NUM_TAG:
                msp_tee_tlv_save(tag, len, value, &tlv_status->sa_instance_num);
                break;
            case APDU_SA_INSTANCE_STATUS_TAG:
                if (tlv_status->instance_count < SA_INSTANCE_MAX_NUM_PER_SA)
                    tlv_status->instance_count++;
                else
                    tlv_status->stop_rcv_sa_instance_status_flg = true;
                break;
            case APDU_SA_INSTANCE_ID_TAG:
                if (tlv_status->stop_rcv_sa_instance_status_flg)
                    break;
                throw_if(tlv_status->instance_count == 0, TEE_ERROR_BAD_PARAMETERS);
                msp_tee_tlv_save(tag, len, value, &tlv_status->instance_id[tlv_status->instance_count - 1]);
                break;
            case APDU_SA_INSTANCE_SELECT_STATUS_TAG:
                if (tlv_status->stop_rcv_sa_instance_status_flg)
                    break;
                throw_if(tlv_status->instance_count == 0, TEE_ERROR_BAD_PARAMETERS);
                msp_tee_tlv_save(tag, len, value, &tlv_status->sa_select_status[tlv_status->instance_count - 1]);
                break;
            default:
                break;
        }
        return TEE_SUCCESS;
    }
    __CATCH
    {
        return ERR_CODE;
    }
}

static uint32_t msp_tee_se_get_sa_status_from_tlv_de(struct sa_tlv_de_sa_status *tlv_status,
                                                     struct sa_status_detail *status)
{
    uint32_t result;
    uint32_t num;
    uint32_t size;
    uint32_t i = 0;

    __TRY
    {
        result = msp_tlv_de_save_u(status->sa_lfc, &tlv_status->sa_lfc);
        throw_if(result != TEE_SUCCESS, result);

        result = msp_tlv_de_save_u(status->sa_instance_num, &tlv_status->sa_instance_num);
        throw_if(result != TEE_SUCCESS, result);

        result = msp_tlv_de_save_u(status->sa_version, &tlv_status->sa_version);
        throw_if(result != TEE_SUCCESS, result);

        result = msp_tlv_de_save_u(status->sa_size, &tlv_status->sa_size);
        throw_if(result != TEE_SUCCESS, result);

        num =
            status->sa_instance_num > SA_INSTANCE_MAX_NUM_PER_SA ? SA_INSTANCE_MAX_NUM_PER_SA : status->sa_instance_num;

        for (i = 0; i < num; i++) {
            size = sizeof(status->instance_status[i].sa_instance_id);
            result = msp_tlv_de_save_u8_list((uint8_t *)(status->instance_status[i]).sa_instance_id, &size,
                                             &(tlv_status->instance_id[i]));
            throw_if(result != TEE_SUCCESS, result);

            if (size != sizeof(status->instance_status[i].sa_instance_id)) {
                tloge("%s[%d], size[%d] error!\n", __func__, __LINE__, size);
                return TEE_ERROR_GENERIC;
            }
            result = msp_tlv_de_save_u(status->instance_status[i].sa_select_status, &tlv_status->sa_select_status[i]);
            throw_if(result != TEE_SUCCESS, result);
        }

        return TEE_SUCCESS;
    }
    __CATCH
    {
        return ERR_CODE;
    }
}

/*
 * @brief      : get sa status form the apdu response
 * @param[in]  : response, the response of apdu command
 * @param[in]  : response_len, the length of the response
 * @param[out] : status, the sa status
 * @return     : TEE_Result
 */
TEE_Result msp_tee_se_get_sa_status_from_apdu_repsonse(const uint8_t *response, uint32_t response_len,
                                                       struct sa_status_detail *status)
{
    struct sa_tlv_de_sa_status *tlv_status = NULL;
    uint32_t result;

    __TRY
    {
        throw_if(response_len < APDU_SW_LEN, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(status, TEE_ERROR_BAD_PARAMETERS);

        tlv_status = TEE_Malloc(sizeof(struct sa_tlv_de_sa_status), 0);
        throw_if_null(tlv_status, TEE_ERROR_OUT_OF_MEMORY);

        result = memset_s(tlv_status, sizeof(*tlv_status), 0, sizeof(*tlv_status));
        throw_if(result != EOK, TEE_ERROR_SECURITY);

        result =
            msp_de_tlv(response, response_len - APDU_SW_LEN, tlv_status, sizeof(*tlv_status), msp_tee_se_de_sa_status);
        throw_if(result != TEE_SUCCESS, result);

        result = msp_tee_se_get_sa_status_from_tlv_de(tlv_status, status);
        throw_if(result != TEE_SUCCESS, result);

        TEE_Free(tlv_status);
        tlv_status = NULL;
        return TEE_SUCCESS;
    }
    __CATCH
    {
        if (tlv_status) {
            TEE_Free(tlv_status);
            tlv_status = NULL;
        }
        return ERR_CODE;
    }
}

/*
 * @brief      : set the apdu command of get sa status privately
 * @param[out] : command, the response of apdu command
 * @param[in]  : sa_aid, the sa aid
 * @param[in]  : sa_aid_len, the length of sa aid
 * @return     : TEE_Result
 */
TEE_Result msp_tee_se_set_get_sa_status(struct apdu_get_status_private *command, const uint8_t *sa_aid,
                                        uint32_t sa_aid_len)
{
    TEE_Result result;
    uint32_t len;

    __TRY
    {
        throw_if_null(command, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(sa_aid, TEE_ERROR_BAD_PARAMETERS);
        throw_if(sa_aid_len != SA_AID_LEN, TEE_ERROR_BAD_PARAMETERS);

        /* CLA: 0x80
         * INS: 0xF3
         * P1: 0x00 GP2.2.1 page165 table 11-33
         * P2: 0x00 GP2.2.1 page166 table 11-34
         * Lc: 0x11
         * DATA:
         * length of SA ID 1 byte
         * SA ID 16 bytes
         * Le 0x00
         */
        command->cla = CLA_CMD;
        command->ins = INS_GET_STATUS_PRIVATE;
        command->p1 = P1_GET_STATUS;
        command->p2 = P2_GET_STATUS;
        command->lc = sizeof(*command) - STD_APDU_HEADER_LEN - APDU_LE_LEN;

        /* add sa_aid */
        len = sizeof(command->sa_aid);
        result = msp_set_tlv(&command->sa_aid, &len, APDU_SA_AID_TAG, sa_aid_len, (const uint8_t *)sa_aid);
        throw_if(result != TEE_SUCCESS, result);
        throw_if(len != sizeof(command->sa_aid), result);

        command->le = 0x00;
        return TEE_SUCCESS;
    }
    __CATCH
    {
        return ERR_CODE;
    }
}
