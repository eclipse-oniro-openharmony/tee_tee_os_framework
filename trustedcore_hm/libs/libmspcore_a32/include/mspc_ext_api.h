/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Header file for msp core extend api.
 * Author : w00371137
 * Create: 2020/02/29
 */

#ifndef __MSPC_EXT_API_H__
#define __MSPC_EXT_API_H__

#include <stdint.h>
#include <tee_internal_api.h>
#define MSPC_EXIST_MAGIC             0x4C
#define MSPC_NOT_AVAILABLE_MAGIC     0xB3

/* must sync with mspc_power.h */
enum mspc_vote_id {
    MSPC_SECFLASH_VOTE_ID        = 0,
    MSPC_BIO_VOTE_ID             = 1,
    MSPC_ROT_VOTE_ID             = 2,
    MSPC_ART_VOTE_ID             = 3,
    MSPC_STRONGBOX_VOTE_ID       = 4,
    MSPC_WEAVER_VOTE_ID          = 5,
    MSPC_FILE_CRYPTO_VOTE_ID     = 6,
    MSPC_FACTORY_VOTE_ID         = 7,
    MSPC_VOICEID_VOTE_ID         = 8,
    MSPC_FINGERPRINT_VOTE_ID     = 9,
    MSPC_FINGERPRINT_UD_VOTE_ID  = 10,
    MSPC_WEAVER_SECTIMER_VOTE_ID = 11,
    MSPC_FACE_VOTE_ID            = 12,
    MSPC_MAX_VOTE_ID             = 13,
};

/*
 * @brief      : TEE_EXT_MSPIsAvailable : Check whether msp core is exist.
 *
 * @param[in]  : status : The status of msp core.
 *               MSPC_EXIST_MAGIC :   msp core is exist.
 *               MSPC_NOT_AVAILABLE_MAGIC : msp core is absence.
 *
 * @return     : SRE_OK: successful, others: failed.
 */
TEE_Result TEE_EXT_MSPIsAvailable(uint32_t *status);

#define MSP_SERVICE_IS_AVAILABLE_MAGIC  0x4C
#define MSP_SERVICE_IS_UNAVAILABLE_MAGIC 0xB3

#define MSP_SERVICE_MAX_COUNT       0x10

#define MSP_SERVICE_MASK            0xFFFFFF00
#define MSP_SERVICE                 0x6D737000 /* "msp" */
#define MSP_SERVICE_SECSTORE        (MSP_SERVICE | 0x00)
#define MSP_SERVICE_FBE             (MSP_SERVICE | 0x01)
#define MSP_SERVICE_ROT             (MSP_SERVICE | 0x02)
#define MSP_SERVICE_WEAVER          (MSP_SERVICE | 0x03)
#define MSP_SERVICE_ART             (MSP_SERVICE | 0x04)

/*
 * @brief      : TEE_EXT_MSPServiceIsAvailable : Check whether msp service is available.
 *
 * @param[in]  : serviceID: the ID of the service which is supported in MSP.
                 isAvailable: The available status of msp services.
 *               MSP_SERVICE_IS_AVAILABLE_MAGIC:   msp service is available.
 *               MSP_SERVICE_IS_UNAVAILABLE_MAGIC: msp service is unavailable.
 *
 * @return     : TEE_SUCCESS: successful, others: failed.
 */
TEE_Result TEE_EXT_MSPServiceIsAvailable(uint32_t serviceID, uint32_t *isAvailable);

/*
 * @brief     : GP Extend TEE API do factory recovery operation about msc device.
 * @param[in] : flags, indicate the operation type, now is not used,fixed as 0xffffffff.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result TEE_EXT_MspcRecovery(uint32_t flags);

/*
 * @brief  : Power on mpsc by voteId. The Power off has to be paired and matched with power on.
 * @param  : voteId for different TA.
 * @return : TEE_SUCCESS: successful, others: failed.
 */
TEE_Result TEE_EXT_MspcPowerOn(uint32_t voteId);

/*
 * @brief  : Power off mpsc by voteId. The Power off has to be paired and matched with power on.
 * @param  : voteId for different TA.
 * @return : TEE_SUCCESS: successful, others: failed.
 */
TEE_Result TEE_EXT_MspcPowerOff(uint32_t voteId);

/*
 * @brief  : Determine if a hardware problem has occurred by mspc errno.
 */
bool TEE_EXT_IsMspcHardwareErrno(uint32_t errno);

#endif /* __MSPC_EXT_API_H__ */
