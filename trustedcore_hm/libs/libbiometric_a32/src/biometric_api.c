/*******************************************************************************
  w
 * All rights reserved, Copyright (C) huawei LIMITED 2019
 * ------------------------------------------------------------------------------
 * File Name   : biometric_api.c
 * Description :
 * Author      : y00362156
 * Version     : 1.0
 * Date        : 2019-10
 * Notes       :
 *
 * ------------------------------------------------------------------------------
 * Modifications:
 *   Date         Author          Modifications
 *******************************************************************************/
/*******************************************************************************
 * This source code has been made available to you by HUAWEI on an
 * AS-IS basis. Anyone receiving this source code is licensed under HUAWEI
 * copyrights to use it in any way he or she deems fit, including copying it,
 * modifying it, compiling it, and redistributing it either with or without
 * modifications. Any person who transfers this source code or any derivative
 * work must include the HUAWEI copyright notice and this paragraph in
 * the transferred software.
 *******************************************************************************/

#include "msp_tee_se_ext_api.h"
#include "biometric_public.h"
#include "tee_service_public.h"
#include "securec.h"
#include "string.h"
#include "ta_framework.h"
#include "tee_log.h"
#include "tee_obj.h"
#include <stdarg.h>
#include "mem_ops_ext.h"
#include "tee_inner_uuid.h"

#define APDU_MAX_LENGTH (32 * 1024 - 16)
#define RES_MAX_LENGTH (32 * 1024 - 16)
#define RES_MIN_LENGTH 2
#define BIO_MAX_USER_NUM 5

#define bio_print tloge

#define __TRY                          \
    uint32_t __errorcode = 0;          \
    uint32_t __errorline = 0xFFFFFFFF; \
    uint32_t __logpara1 = 0;

#define __CATCH \
    __tabErr:   \
    bio_print("[%s] line(%d),error(%u),para(%u)\n", __FUNCTION__, __errorline, __errorcode, __logpara1);

#define SET_PARA(para)                 \
    {                                  \
        __logpara1 = (uint32_t)(para); \
    }
#define ERR_PROC()              \
    {                           \
        __errorline = __LINE__; \
        goto __tabErr;          \
    }
#define THROW(errcode)           \
    {                            \
        __errorcode = (errcode); \
        ERR_PROC()               \
    }
#define THROW_IF(expr, errcode) \
    {                           \
        if (expr) {             \
            THROW(errcode)      \
        }                       \
    }
#define THROW_IF_NULL(ptr, errcode) \
    {                               \
        if (!(ptr)) {               \
            THROW(errcode)          \
        }                           \
    }
#define THROW_IF_WITH_PARA(expr, errcode, para) \
    {                                           \
        if (expr) {                             \
            SET_PARA(para);                     \
            THROW(errcode)                      \
        }                                       \
    }

#define ERR_CODE (__errorcode)

static const TEE_UUID g_bio_uuid = TEE_SERVICE_BIO;
/*
 * @brief     : GP Extend TEE API load SA to msp operation.
 * @param[in] : sa_image, the image buffer of SA.
 * @param[in] : length of the SA image. 
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_EXT_BioLoadSA(const char *sa_image, uint32_t image_length)
{
    tee_service_ipc_msg msg = { { 0 } };
    tee_service_ipc_msg_rsp rsp = { 0 };
    TEE_Result ret;
    char *sa_image_local = NULL;

    __TRY {
        THROW_IF_NULL(sa_image, TEE_ERROR_BAD_PARAMETERS);
        THROW_IF(image_length == 0, TEE_ERROR_BAD_PARAMETERS);

        sa_image_local = (char *)tee_alloc_sharemem_aux(&g_bio_uuid, image_length);
        THROW_IF_NULL(sa_image_local, TEE_ERROR_GENERIC);

        ret = memmove_s(sa_image_local, image_length, sa_image, image_length);
        THROW_IF(ret != EOK, TEE_ERROR_SECURITY);

        msg.args_data.arg0 = (uintptr_t)sa_image_local;
        msg.args_data.arg1 = image_length;

        tee_common_ipc_proc_cmd(BIO_TASK_NAME, BIO_MSG_EXT_LOAD_CMD, &msg, BIO_MSG_EXT_LOAD_CMD, &rsp);

        THROW_IF(rsp.ret != TEE_SUCCESS, rsp.ret);

        (void)memset_s(sa_image_local, image_length, 0, image_length);
        (void)__SRE_MemFreeShared(sa_image_local, image_length);
        return TEE_SUCCESS;
    }
    __CATCH {
        if (sa_image_local != NULL) {
            (void)memset_s(sa_image_local, image_length, 0, image_length);
            (void)__SRE_MemFreeShared(sa_image_local, image_length);
        }
        return ERR_CODE;
    }
}

/*
 * @brief     : GP Extend TEE API install SA in msp operation.
 * @param[in] : sa_image, the image buffer of SA.
 * @param[in] : length of the SA image. 
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_EXT_BioInstallSA(uint32_t nvm_data_size, uint32_t version, uint16_t *sa_lfc)
{
    tee_service_ipc_msg msg = { { 0 } };
    tee_service_ipc_msg_rsp rsp = { 0 };
    struct msp_install_sa_info *install_sa_info_local = NULL;
    uint32_t install_sa_info_len = sizeof(struct msp_install_sa_info);
    struct sa_status *status_local = NULL;
    uint32_t status_len = sizeof(struct sa_status);

    __TRY {
        THROW_IF_NULL(sa_lfc, TEE_ERROR_GENERIC);

        install_sa_info_local = (struct msp_install_sa_info *)tee_alloc_sharemem_aux(&g_bio_uuid, install_sa_info_len);
        THROW_IF_NULL(install_sa_info_local, TEE_ERROR_GENERIC);

        install_sa_info_local->user_id = 0;
        install_sa_info_local->nvm_data_size = nvm_data_size;
        install_sa_info_local->version = version;

        status_local = (struct sa_status *)tee_alloc_sharemem_aux(&g_bio_uuid, status_len);
        THROW_IF_NULL(status_local, TEE_ERROR_GENERIC);

        msg.args_data.arg0 = (uintptr_t)install_sa_info_local;
        msg.args_data.arg1 = (uintptr_t)status_local;

        tee_common_ipc_proc_cmd(BIO_TASK_NAME, BIO_MSG_EXT_INSTALL_CMD, &msg, BIO_MSG_EXT_INSTALL_CMD, &rsp);

        THROW_IF(rsp.ret != TEE_SUCCESS, rsp.ret);

        (void)__SRE_MemFreeShared(install_sa_info_local, install_sa_info_len);

        *sa_lfc = status_local->sa_lfc;
        (void)__SRE_MemFreeShared(status_local, status_len);

        return TEE_SUCCESS;
    }
    __CATCH {
        if (install_sa_info_local != NULL) {
            (void)memset_s(install_sa_info_local, install_sa_info_len, 0, install_sa_info_len);
            (void)__SRE_MemFreeShared(install_sa_info_local, install_sa_info_len);
        }

        if (status_local != NULL) {
            (void)memset_s(status_local, status_len, 0, status_len);
            (void)__SRE_MemFreeShared(status_local, status_len);
        }
        return ERR_CODE;
    }
}

/*
 * @brief     : GP Extend TEE API start SA operation.
 * @param[in] : user_id, The ID of current user.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_EXT_BioStartSA()
{
    tee_service_ipc_msg msg = { { 0 } };
    tee_service_ipc_msg_rsp rsp = { 0 };

    __TRY {
        tee_common_ipc_proc_cmd(BIO_TASK_NAME, BIO_MSG_EXT_START_CMD, &msg, BIO_MSG_EXT_START_CMD, &rsp);

        THROW_IF(rsp.ret != TEE_SUCCESS, rsp.ret);
        return TEE_SUCCESS;
    }
    __CATCH {
        return ERR_CODE;
    }
}

/*
 * @brief     : GP Extend TEE API send command operation that called by TA.
 * @param[in] : apdu_buffer, Pointer to apdu command buffer.
 * @param[in] : apdu_length, Length of apdu command.
 * @param[in] : out_length, Length of out_buffer.
 * @param[out]: out_buffer, Pointer to command response.
 * @param[in/out]: out_length, Length of response.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_EXT_BioSendCommand(uint8_t *apdu_buffer, uint32_t apdu_length, uint8_t *out_buffer, uint32_t *out_length)
{
    tee_service_ipc_msg msg = { { 0 } };
    tee_service_ipc_msg_rsp rsp = { 0 };
    TEE_Result ret = TEE_ERROR_GENERIC;
    char *apdu_buffer_local = NULL;
    char *out_buffer_local = NULL;
    uint32_t *out_length_local = NULL;
    uint32_t out_buf_len;
    uint32_t out_len_len = sizeof(uint32_t);


    __TRY {
        THROW_IF_NULL(apdu_buffer, TEE_ERROR_BAD_PARAMETERS);
        THROW_IF_NULL(out_buffer, TEE_ERROR_BAD_PARAMETERS);
        THROW_IF_NULL(out_length, TEE_ERROR_BAD_PARAMETERS);


        out_buf_len = *out_length;
        THROW_IF((out_buf_len < RES_MIN_LENGTH) || (out_buf_len > RES_MAX_LENGTH), TEE_ERROR_BAD_PARAMETERS);
        THROW_IF(apdu_length > APDU_MAX_LENGTH, TEE_ERROR_BAD_PARAMETERS);
        THROW_IF(apdu_length == 0, TEE_ERROR_BAD_PARAMETERS);
        apdu_buffer_local = (char *)tee_alloc_sharemem_aux(&g_bio_uuid, apdu_length);
        THROW_IF_NULL(apdu_buffer_local, TEE_ERROR_OUT_OF_MEMORY);

        out_buffer_local = (char *)tee_alloc_sharemem_aux(&g_bio_uuid, *out_length);
        THROW_IF_NULL(out_buffer_local, TEE_ERROR_OUT_OF_MEMORY);

        out_length_local = (uint32_t *)tee_alloc_sharemem_aux(&g_bio_uuid, out_len_len);
        THROW_IF_NULL(out_length_local, TEE_ERROR_OUT_OF_MEMORY);

        *out_length_local = *out_length;

        ret = memmove_s(apdu_buffer_local, apdu_length, apdu_buffer, apdu_length);
        THROW_IF(ret != EOK, TEE_ERROR_SECURITY);

        msg.args_data.arg0 = (uintptr_t)apdu_buffer_local;
        msg.args_data.arg1 = apdu_length;
        msg.args_data.arg2 = (uintptr_t)out_buffer_local;
        msg.args_data.arg3 = (uintptr_t)out_length_local;
        rsp.ret = TEE_ERROR_GENERIC;

        tee_common_ipc_proc_cmd(BIO_TASK_NAME, BIO_MSG_EXT_SEND_CMD, &msg, BIO_MSG_EXT_SEND_CMD, &rsp);
        THROW_IF(rsp.ret != TEE_SUCCESS, rsp.ret);

        if (*out_length < *out_length_local) {
            THROW(TEE_ERROR_SECURITY);
        }

        ret = memmove_s(out_length, out_len_len, out_length_local, out_len_len);
        THROW_IF(ret != EOK, TEE_ERROR_SECURITY);

        ret = memmove_s(out_buffer, *out_length, out_buffer_local, *out_length);
        THROW_IF(ret != EOK, TEE_ERROR_SECURITY);

        (void)memset_s(apdu_buffer_local, apdu_length, 0, apdu_length);
        (void)__SRE_MemFreeShared(apdu_buffer_local, apdu_length);
        (void)memset_s(out_buffer_local, out_buf_len, 0, out_buf_len);
        (void)__SRE_MemFreeShared(out_buffer_local, out_buf_len);
        (void)memset_s(out_length_local, out_len_len, 0, out_len_len);
        (void)__SRE_MemFreeShared(out_length_local, out_len_len);
        return TEE_SUCCESS;
    }
    __CATCH {
        if (apdu_buffer_local != NULL) {
            (void)memset_s(apdu_buffer_local, apdu_length, 0, apdu_length);
            (void)__SRE_MemFreeShared(apdu_buffer_local, apdu_length);
        }
        if (out_buffer_local != NULL) {
            (void)memset_s(out_buffer_local, out_buf_len, 0, out_buf_len);
            (void)__SRE_MemFreeShared(out_buffer_local, out_buf_len);
        }
        if (out_length_local != NULL) {
            (void)memset_s(out_length_local, out_len_len, 0, out_len_len);
            (void)__SRE_MemFreeShared(out_length_local, out_len_len);
        }
        return ERR_CODE;
    }
}

/*
 * @brief     : GP Extend TEE API close SA operation.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_EXT_BioCloseSA(void)
{
    tee_service_ipc_msg msg = { { 0 } };
    tee_service_ipc_msg_rsp rsp = { 0 };

    __TRY {
        tee_common_ipc_proc_cmd(BIO_TASK_NAME, BIO_MSG_EXT_CLOSE_CMD, &msg, BIO_MSG_EXT_CLOSE_CMD, &rsp);
        THROW_IF(rsp.ret != TEE_SUCCESS, rsp.ret);
        return TEE_SUCCESS;
    }
    __CATCH {
        return ERR_CODE;
    }
}
/*
 * @brief     : GP Extend TEE API reinit the status about SA.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_EXT_BioReInit(void)
{
    tee_service_ipc_msg msg = { { 0 } };
    tee_service_ipc_msg_rsp rsp = { 0 };

    __TRY {
        tee_common_ipc_proc_cmd(BIO_TASK_NAME, BIO_MSG_EXT_REINIT_CMD, &msg, BIO_MSG_EXT_REINIT_CMD, &rsp);
        THROW_IF(rsp.ret != TEE_SUCCESS, rsp.ret);

        return TEE_SUCCESS;
    }
    __CATCH {
        return ERR_CODE;
    }
}
