/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Create: 2012-03-20
 * Description: Tee ext api header file
 */

#ifndef TEE_EXT_API_H
#define TEE_EXT_API_H

#include "tee_defines.h"
#include "tee_hw_ext_api_legacy.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#ifndef CONFIG_OH_PLATFORM
/*
 * below definitions are defined by Platform SDK released previously
 * for compatibility:
 * don't make any change to the content below
 */
#define TEE_RETURN_AGENT_BUFFER 0x99
#define TEE_INVALID_AGENT       0x66
#define TEE_AGENT_LOCK          0x33

#define TEE_GET_REEINFO_SUCCESS 0
#define TEE_GET_REEINFO_FAILED  1

#define TEE_SMC_FROM_USR    0
#define TEE_SMC_FROM_KERNEL 1

#define RESERVED_BUF_SIZE 32
typedef struct ta_caller_info {
    uint32_t session_type;
    union {
        TEE_UUID caller_uuid;
        uint8_t ca_info[RESERVED_BUF_SIZE];
    } caller_identity;
    uint8_t smc_from_kernel_mode;
    uint8_t reserved[RESERVED_BUF_SIZE - 1];
} caller_info;

/*
 * Get caller info of current session, refer caller_info struct for more details
 *
 * @param caller_info_data [OUT] caller info to be returned
 * @param length           [IN] sizeof struct caller_info
 *
 * return TEE_SUCCESS operation success
 * return others failed to get caller info
 */
TEE_Result tee_ext_get_caller_info(caller_info *caller_info_data, uint32_t length);
#endif

/*
 * TA can call this API to add caller's info,
 * which is allowed to call this TA.
 * this API is for CA in form of binary-excuteble file.
 *
 * @param ca_name     [IN]        CA caller's process name
 * @param ca_uid      [IN]        CA caller's uid
 *
 * return TEE_SUCCESS operation
 * return others failed to add caller info for target CA
 */
TEE_Result AddCaller_CA_exec(const char *ca_name, uint32_t ca_uid);
/*
 * TA can call this API to add caller's info,
 * which is allowed to call this TA.
 * this API is for CA in form of APK.
 *
 * @param ca_name       [IN]        CA caller's packagename
 * @param modulus       [IN]        CA caller's modulus
 * @param pub_exponent  [IN]        CA caller's pub_exponent
 *
 * return TEE_SUCCESS operation
 * return others failed to add caller info for target CA
 */
TEE_Result AddCaller_CA_apk(const char *ca_name, const char *modulus, const char *pub_exponent);

#ifndef CONFIG_OH_PLATFORM
/*
 * TA call this API allow others TA open session with itself
 *
 * return TEE_SUCCESS operation success
 * result others operation failed
 */
TEE_Result AddCaller_TA_all(void);

#define SESSION_FROM_CA      0
#define SESSION_FROM_TA      1
#define SESSION_FROM_UNKNOWN 0xFF
/*
 * get cruurent session type
 *
 * @return session type of current session
 */
uint32_t tee_get_session_type(void);

/*
 * Check CA params during CA Authentication
 *
 * @param param_types             [IN] CA caller's param types
 * @param params[TEE_PARAMS_NUM]  [IN] CA caller's params
 *
 * return TEE_SUCCESS
 */
TEE_Result TEE_EXT_CheckClientPerm(uint32_t param_types, const TEE_Param params[TEE_PARAMS_NUM]);
#endif
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#endif
