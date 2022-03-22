/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#define SASI_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_INFRA

#include "sym_adaptor_driver.h"
#include "ssi_pal_types.h"
#include "ssi_pal_mem.h"
#include "cipher.h"

#if (DX_DSCRPTR_QUEUE0_WORD3_NS_BIT_BIT_SHIFT != DX_DSCRPTR_QUEUE0_WORD1_NS_BIT_BIT_SHIFT) || \
    (DX_DSCRPTR_QUEUE0_WORD1_DIN_VIRTUAL_HOST_BIT_SHIFT != DX_DSCRPTR_QUEUE0_WORD3_DOUT_VIRTUAL_HOST_BIT_SHIFT)
#error AxiId/NS-bit fields mismatch between DIN and DOUT - functions need to be updated...
#endif

/*
 * Parse user buffer information that may be smart key pointer (key object)
 * Return uniform Key information
 *
 *
 * \param [in]  keyObj - the key buffer
 * \param [out] keyAddr - key pointer
 * \param [out] cryptoKeyType - type of key (ROOT, USER,PROVISIONING ...)
 * \param [out] keyPtrType  - type of pointer (SRAM ptr, DCAHE ptr, DLLI ptr)
 *
 * \return 0 on success, (-1) on error
 */
int getKeyDataFromKeyObj(uint8_t *keyObj, uint8_t **keyAddr, enum drv_crypto_key_type *cryptoKeyType,
                         KeyPtrType_t *keyPtrType, enum SaSiDataKeyObjApi_t cryptoObjApi)
{
    /* in the CC we use only user key in DLLI mode */
    *keyAddr       = keyObj;
    *cryptoKeyType = DRV_USER_KEY;
    *keyPtrType    = KEY_BUF_DLLI;
    cryptoObjApi   = cryptoObjApi;

    return 0;
}
