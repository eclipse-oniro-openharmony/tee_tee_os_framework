/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: PIN security enhancement.
 * Create: 2021-06-07
 */
#ifndef PIN_CODE_API_H
#define PIN_CODE_API_H
#include <tee_internal_api.h>

#define unused (void)
/* return code */
typedef enum _pin_result_ {
    PINCODE_SUCCESS = TEE_SUCCESS,
    PINCODE_ERR_NOT_SUPPORTED = 0xA40F0001,
    PINCODE_ERR_BAD_PARAMS,         /* 0xA40F0002 */
    PINCODE_ERR_BAD_LENGTH,         /* 0xA40F0003 */
    PINCODE_ERR_RPMB_READ_FAILED,   /* 0xA40F0004 */
    PINCODE_ERR_RPMB_WRITE_FAILED,  /* 0xA40F0005 */
    PINCODE_ERR_COS_UNREADY,        /* 0xA40F0006 */
    PINCODE_ERR_SHORT_BUFFER,       /* 0xA40F0007 */
    PINCODE_ERR_SECURITY,           /* 0xA40F0008 */
    PINCODE_ERR_RAPDU_ILLEGAL,      /* 0xA40F0009 */
    PINCODE_ERR_BAD_RAPDU_LEN,      /* 0xA40F000A */
    PINCODE_ERR_DERIVE_KEY,         /* 0xA40F000B */
    PINCODE_ERR_ALLOC_OBJ_ERR,      /* 0xA40F000C */
    PINCODE_ERR_ALLOC_HANDLE_ERR,   /* 0xA40F000D */
    PINCODE_ERR_SET_KEY_ERR,        /* 0xA40F000E */
    PINCODE_ERR_SET_CRYPTO_ERR,     /* 0xA40F000F */
    PINCODE_ERR_HMAC_INIT,          /* 0xA40F0010 */
    PINCODE_ERR_HMAC_UPDATE,        /* 0xA40F0011 */
    PINCODE_ERR_HMAC_DOFINAL,       /* 0xA40F0012 */
    PINCODE_ERR_VERIFY_PIN,         /* 0xA40F0013 */
    PINCODE_ERR_UNKNOWN,            /* 0xA40F000E */
} pin_result;

#define pincode_err_others(sw)  (0xA40F0000 | (sw))

/* structure of parameters */
struct memref_in {
    const uint8_t *buffer;
    uint32_t length;
};

struct memref_out {
    uint8_t *buffer;
    uint32_t *size; /* the maximum size of buffer in bytes for input, the real size of buffer in bytes for output. */
};

/*
 * @brief        : registers pin.
 * @param[in]    : key_id, the key id.
 * @param[in]    : pin, pin hash value.
 * @param[out]   : handle, the handle of the PIN.
 * @param[out]   : key_factor, the key factor used for generate handle.
 * @return       : Operation status, success(0) or other failure status.
 */
inline TEE_Result tee_ext_pincode_register_pin(const struct memref_in *key_id, const struct memref_in *pin,
                                        struct memref_out *handle, struct memref_out *key_factor)
{
    unused(key_id);
    unused(pin);
    unused(handle);
    unused(key_factor);
    return PINCODE_ERR_NOT_SUPPORTED;
}

/*
 * @brief        : verifies pin.
 * @param[in]    : key_id, the key id.
 * @param[in]    : pin, pin hash value.
 * @param[in]    : handle, the handle of the PIN.
 * @param[out]   : key_factor, the key factor used for generate handle.
 * @return       : Operation status, success(0) or other failure status.
 */
inline TEE_Result tee_ext_pincode_verify_pin(const struct memref_in *key_id, const struct memref_in *pin,
                                      const struct memref_in *handle, struct memref_out *key_factor)
{
    unused(key_id);
    unused(pin);
    unused(handle);
    unused(key_factor);
    return PINCODE_ERR_NOT_SUPPORTED;
}

/*
 * @brief        : power on the chip.
 * @return       : Operation status, success(0) or other failure status.
 */
inline TEE_Result tee_ext_pincode_poweron(void)
{
    return PINCODE_ERR_NOT_SUPPORTED;
}

/*
 * @brief        : power off the chip.
 * @return       : Operation status, success(0) or other failure status.
 */
inline TEE_Result tee_ext_pincode_poweroff(void)
{
    return PINCODE_ERR_NOT_SUPPORTED;
}

#endif
