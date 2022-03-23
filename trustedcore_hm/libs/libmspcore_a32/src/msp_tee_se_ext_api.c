/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: msp tee se ext api
 * Author: z00387284
 * Create: 2019-10-21
 */
#include "msp_tee_se_ext_api.h"
#include <tee_internal_se_api.h>
#include "art_public.h"
#include "hisee_try_catch.h"
#include "securec.h"
#include "tee_service_public.h"
#include "mem_ops_ext.h"
#include "tee_inner_uuid.h"

static const TEE_UUID g_art_uuid = TEE_SERVICE_ART;

#ifdef CONFIG_HISI_MSPC
/*
 * @brief      : the tee ext api-------load sa
 * @param[in]  : sa_image, the sa image
 * @param[in]  : sa_image_len, the length of the sa image
 * @param[in]  : sa_aid, the sa aid
 * @param[in]  : sa_aid_len, the length of the sa aid
 * @return     : TEE_Result
 */
TEE_Result TEE_EXT_MSPLoadSA(const uint8_t *sa_image, uint32_t sa_image_len, const uint8_t *sa_aid, uint32_t sa_aid_len)
{
    TEE_Result result;
    uint8_t *sa_image_local = NULL;
    uint8_t *sa_aid_local = NULL;
    tee_service_ipc_msg msg = { { 0 } };
    tee_service_ipc_msg_rsp rsp = {0};

    __TRY
    {
        throw_if_null(sa_aid, TEE_ERROR_BAD_PARAMETERS);
        throw_if(sa_aid_len != SA_AID_LEN, TEE_ERROR_BAD_PARAMETERS);

        if (sa_image_len != 0) {
            throw_if_null(sa_image, TEE_ERROR_BAD_PARAMETERS);
            sa_image_local = (uint8_t *)tee_alloc_sharemem_aux(&g_art_uuid, sa_image_len);
            throw_if_null(sa_image_local, TEE_ERROR_GENERIC);

            result = memmove_s(sa_image_local, sa_image_len, sa_image, sa_image_len);
            throw_if(result != EOK, TEE_ERROR_SECURITY);
        }

        sa_aid_local = (uint8_t *)tee_alloc_sharemem_aux(&g_art_uuid, sa_aid_len);
        throw_if_null(sa_aid_local, TEE_ERROR_GENERIC);

        result = memmove_s(sa_aid_local, sa_aid_len, sa_aid, sa_aid_len);
        throw_if(result != EOK, TEE_ERROR_SECURITY);

        msg.args_data.arg0 = (uintptr_t)sa_image_local;
        msg.args_data.arg1 = sa_image_len;
        msg.args_data.arg2 = (uintptr_t)sa_aid_local;
        msg.args_data.arg3 = sa_aid_len;

        tee_common_ipc_proc_cmd(ART_TASK_NAME, SAMGR_MSG_EXT_LOAD_CMD, &msg, SAMGR_MSG_EXT_LOAD_CMD, &rsp);

        throw_if(rsp.ret != TEE_SUCCESS, rsp.ret);

        if (sa_image_len != 0) {
            result = memset_s(sa_image_local, sa_image_len, 0, sa_image_len);
            throw_if(result != EOK, TEE_ERROR_SECURITY);
            (void)__SRE_MemFreeShared(sa_image_local, sa_image_len);
            sa_image_local = NULL;
        }

        result = memset_s(sa_aid_local, sa_aid_len, 0, sa_aid_len);
        throw_if(result != EOK, TEE_ERROR_SECURITY);
        (void)__SRE_MemFreeShared(sa_aid_local, sa_aid_len);
        sa_aid_local = NULL;

        return TEE_SUCCESS;
    }
    __CATCH
    {
        if (sa_image_local != NULL) {
            (void)memset_s(sa_image_local, sa_image_len, 0, sa_image_len);
            (void)__SRE_MemFreeShared(sa_image_local, sa_image_len);
            sa_image_local = NULL;
        }

        if (sa_aid_local != NULL) {
            (void)memset_s(sa_aid_local, sa_aid_len, 0, sa_aid_len);
            (void)__SRE_MemFreeShared(sa_aid_local, sa_aid_len);
            sa_aid_local = NULL;
        }

        return ERR_CODE;
    }
}

/*
 * @brief      : the tee ext api-------install sa
 * @param[in]  : install_sa_info, the info about installing sa, see the struct msp_install_sa_info
 * @param[out] : status, the sa status, see the struct sa_status
 * @return     : TEE_Result
 */
TEE_Result TEE_EXT_MSPInstallSA(const struct msp_install_sa_info *install_sa_info, struct sa_status *status)
{
    TEE_Result result;
    struct sa_status *status_local = NULL;
    struct msp_install_sa_info *install_sa_info_local = NULL;
    tee_service_ipc_msg msg = { { 0 } };
    tee_service_ipc_msg_rsp rsp = {0};

    __TRY
    {
        throw_if_null(install_sa_info, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(status, TEE_ERROR_BAD_PARAMETERS);

        /* the 15 bytes of sa_intance_id need be same as the sa_aid, not support multi-instance now */
        throw_if(memcmp(install_sa_info->sa_aid, install_sa_info->sa_instance_id, SA_AID_LEN - 1) != 0,
                 TEE_ERROR_BAD_PARAMETERS);
        /* the last byte of sa_intance_id need be '0'~'9', not support multi-instance now */
        throw_if((install_sa_info->sa_instance_id)[SA_AID_LEN - 1] > '9', TEE_ERROR_BAD_PARAMETERS);
        throw_if((install_sa_info->sa_instance_id)[SA_AID_LEN - 1] < '0', TEE_ERROR_BAD_PARAMETERS);

        install_sa_info_local =
            (struct msp_install_sa_info *)tee_alloc_sharemem_aux(&g_art_uuid, sizeof(struct msp_install_sa_info));
        throw_if_null(install_sa_info_local, TEE_ERROR_GENERIC);

        result = memmove_s(install_sa_info_local, sizeof(struct msp_install_sa_info),
                           install_sa_info, sizeof(struct msp_install_sa_info));
        throw_if(result != EOK, TEE_ERROR_SECURITY);

        status_local = (struct sa_status *)tee_alloc_sharemem_aux(&g_art_uuid, sizeof(struct sa_status));
        throw_if_null(status_local, TEE_ERROR_GENERIC);

        msg.args_data.arg0 = (uintptr_t)install_sa_info_local;
        msg.args_data.arg1 = (uintptr_t)status_local;

        tee_common_ipc_proc_cmd(ART_TASK_NAME, SAMGR_MSG_EXT_INSTALL_CMD, &msg, SAMGR_MSG_EXT_INSTALL_CMD, &rsp);

        throw_if(rsp.ret != TEE_SUCCESS, rsp.ret);

        (void)memset_s(install_sa_info_local, sizeof(struct msp_install_sa_info),
                       0, sizeof(struct msp_install_sa_info));
        (void)__SRE_MemFreeShared(install_sa_info_local, sizeof(struct msp_install_sa_info));
        install_sa_info_local = NULL;

        status->sa_version = status_local->sa_version;
        status->sa_lfc = status_local->sa_lfc;
        status->sa_instance_num = status_local->sa_instance_num;

        result = memcpy_s(&(status->instance_status), sizeof(status->instance_status), &(status_local->instance_status),
                          sizeof(status_local->instance_status));
        throw_if(result != EOK, TEE_ERROR_SECURITY);

        (void)memset_s(status_local, sizeof(struct sa_status), 0, sizeof(struct sa_status));
        (void)__SRE_MemFreeShared(status_local, sizeof(struct sa_status));
        status_local = NULL;

        return TEE_SUCCESS;
    }
    __CATCH
    {
        if (install_sa_info_local != NULL) {
            (void)memset_s(install_sa_info_local, sizeof(struct msp_install_sa_info),
                           0, sizeof(struct msp_install_sa_info));
            (void)__SRE_MemFreeShared(install_sa_info_local, sizeof(struct msp_install_sa_info));
            install_sa_info_local = NULL;
        }

        if (status_local != NULL) {
            (void)memset_s(status_local, sizeof(struct sa_status), 0, sizeof(struct sa_status));
            (void)__SRE_MemFreeShared(status_local, sizeof(struct sa_status));
            status_local = NULL;
        }

        return ERR_CODE;
    }
}

/*
 * @brief      : the tee ext api-------get sa status
 * @param[in]  : sa_aid, the sa aid
 * @param[in]  : sa_aid_len, the length of sa aid
 * @param[out] : status, the sa status, see the struct sa_status_detail
 * @return     : TEE_Result
 */
TEE_Result TEE_EXT_MSPGetStatus(const uint8_t *sa_aid, uint32_t sa_aid_len, struct sa_status_detail *status)
{
    TEE_Result result;
    uint8_t *sa_aid_local = NULL;
    struct sa_status_detail *status_detail_local = NULL;
    tee_service_ipc_msg msg = { { 0 } };
    tee_service_ipc_msg_rsp rsp = {0};

    __TRY
    {
        throw_if_null(sa_aid, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(status, TEE_ERROR_BAD_PARAMETERS);
        throw_if(sa_aid_len != SA_AID_LEN, TEE_ERROR_BAD_PARAMETERS);

        sa_aid_local = (uint8_t *)tee_alloc_sharemem_aux(&g_art_uuid, sa_aid_len);
        throw_if_null(sa_aid_local, TEE_ERROR_GENERIC);

        result = memmove_s(sa_aid_local, sa_aid_len, sa_aid, sa_aid_len);
        throw_if(result != EOK, TEE_ERROR_SECURITY);

        status_detail_local =
            (struct sa_status_detail *)tee_alloc_sharemem_aux(&g_art_uuid, sizeof(struct sa_status_detail));
        throw_if_null(status_detail_local, TEE_ERROR_GENERIC);

        msg.args_data.arg0 = (uintptr_t)sa_aid_local;
        msg.args_data.arg1 = sa_aid_len;
        msg.args_data.arg2 = (uintptr_t)status_detail_local;

        tee_common_ipc_proc_cmd(ART_TASK_NAME, SAMGR_MSG_EXT_GETSTATUS_CMD, &msg, SAMGR_MSG_EXT_GETSTATUS_CMD, &rsp);

        throw_if(rsp.ret != TEE_SUCCESS, rsp.ret);

        (void)memset_s(sa_aid_local, sa_aid_len, 0, sa_aid_len);
        (void)__SRE_MemFreeShared(sa_aid_local, sa_aid_len);
        sa_aid_local = NULL;

        result = memmove_s(status, sizeof(struct sa_status_detail),
                           status_detail_local, sizeof(struct sa_status_detail));
        throw_if(result != EOK, TEE_ERROR_SECURITY);

        (void)memset_s(status_detail_local, sizeof(struct sa_status_detail), 0, sizeof(struct sa_status_detail));
        (void)__SRE_MemFreeShared(status_detail_local, sizeof(struct sa_status_detail));
        status_detail_local = NULL;

        return TEE_SUCCESS;
    }
    __CATCH
    {
        if (sa_aid_local != NULL) {
            (void)memset_s(sa_aid_local, sa_aid_len, 0, sa_aid_len);
            (void)__SRE_MemFreeShared(sa_aid_local, sa_aid_len);
            sa_aid_local = NULL;
        }

        if (status_detail_local != NULL) {
            (void)memset_s(status_detail_local, sizeof(struct sa_status_detail), 0, sizeof(struct sa_status_detail));
            (void)__SRE_MemFreeShared(status_detail_local, sizeof(struct sa_status_detail));
            status_detail_local = NULL;
        }

        return ERR_CODE;
    }
}
#else

TEE_Result TEE_EXT_MSPLoadSA(const uint8_t *sa_image, uint32_t sa_image_len, const uint8_t *sa_aid, uint32_t sa_aid_len)
{
    (void)sa_image;
    (void)sa_image_len;
    (void)sa_aid;
    (void)sa_aid_len;

    return TEE_ERROR_SERVICE_NOT_EXIST;
}

TEE_Result TEE_EXT_MSPInstallSA(const struct msp_install_sa_info *install_sa_info, struct sa_status *status)
{
    (void)install_sa_info;
    (void)status;

    return TEE_ERROR_SERVICE_NOT_EXIST;
}

TEE_Result TEE_EXT_MSPGetStatus(const uint8_t *sa_aid, uint32_t sa_aid_len, struct sa_status_detail *status)
{
    (void)sa_aid;
    (void)sa_aid_len;
    (void)status;

    return TEE_ERROR_SERVICE_NOT_EXIST;
}

#endif
