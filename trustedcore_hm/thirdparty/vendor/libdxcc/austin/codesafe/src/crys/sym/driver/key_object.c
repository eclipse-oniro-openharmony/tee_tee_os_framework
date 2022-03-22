/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

#define DX_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_INFRA

#include "dx_pal_types.h"
#include "sep_ctx.h"
#include "crys_aes.h"
#include "key_buffer.h"
#include "key_object.h"
#include "compiler.h"

DX_PAL_COMPILER_ASSERT(sizeof(KeyBuffer_s) <= sizeof(DX_KeyObjContainer_t), "Container size is too small");

#define HANDLE_TO_OBJ(ptr)  PTR_TO_KEY_BUFFER(ptr)
#define OBJ_TO_HANDLE(pObj) KEY_BUFFER_TO_PTR(pObj)

/* !
 * Create a Key object for key buffer for user key in SRAM
 *
 * \param container A memory allocated by the caller to accomodate the object
 * \param aKeyAddr user key pointer
 * \return DX_KeyObjHandle_t The created object handle
 */
DX_KeyObjHandle_t DX_KeyObjCreateSepUserKey(DX_KeyObjContainer_t container, uint32_t aKeyAddr)
{
    KeyBuffer_s *newObj = (KeyBuffer_s *)container;

    newObj->cryptoKeyType = SEP_USER_KEY;
    newObj->pKey          = (uint8_t *)aKeyAddr;
    newObj->keyPtrType    = KEY_BUF_SEP;
    return OBJ_TO_HANDLE(newObj);
}

/* !
 * Create a Key object for key buffer for user key in HOST
 *
 * \param container A memory allocated by the caller to accomodate the object
 * \param aKeyAddr user key pointer
 * \return DX_KeyObjHandle_t The created object handle
 */
DX_KeyObjHandle_t DX_KeyObjCreateHostUserKey(DX_KeyObjContainer_t container, uint32_t aKeyAddr)
{
    KeyBuffer_s *newObj = (KeyBuffer_s *)container;

    newObj->cryptoKeyType = SEP_USER_KEY;
    newObj->pKey          = (uint8_t *)aKeyAddr;
    newObj->keyPtrType    = KEY_BUF_DLLI;
    return OBJ_TO_HANDLE(newObj);
}

/* !
 * Create a Key object for key buffer for ROOT key
 *
 * \param container A memory allocated by the caller to accomodate the object
 * \return DX_KeyObjHandle_t The created object handle
 */
DX_KeyObjHandle_t DX_KeyObjCreateRkekKey(DX_KeyObjContainer_t container)
{
    KeyBuffer_s *newObj = (KeyBuffer_s *)container;

    newObj->cryptoKeyType = SEP_ROOT_KEY;
    newObj->pKey          = DX_NULL;
    newObj->keyPtrType    = KEY_BUF_NULL;
    return OBJ_TO_HANDLE(newObj);
}

/* !
 * Create a Key object for key buffer for APPLET key
 *
 * \param container A memory allocated by the caller to accomodate the object
 * \return DX_KeyObjHandle_t The created object handle
 */
DX_KeyObjHandle_t DX_KeyObjCreateAppletKey(DX_KeyObjContainer_t container)
{
    KeyBuffer_s *newObj = (KeyBuffer_s *)container;

    newObj->cryptoKeyType = SEP_APPLET_KEY;
    newObj->pKey          = DX_NULL;
    newObj->keyPtrType    = KEY_BUF_NULL;
    return OBJ_TO_HANDLE(newObj);
}

/* !
 * Create a Key object for key buffer for Provisioning key
 *
 * \param container A memory allocated by the caller to accomodate the object
 * \return DX_KeyObjHandle_t The created object handle
 */
DX_KeyObjHandle_t DX_KeyObjCreateProvKey(DX_KeyObjContainer_t container)
{
    KeyBuffer_s *newObj = (KeyBuffer_s *)container;

    newObj->cryptoKeyType = SEP_PROVISIONING_KEY;
    newObj->pKey          = DX_NULL;
    newObj->keyPtrType    = KEY_BUF_NULL;
    return OBJ_TO_HANDLE(newObj);
}

/* !
 * Create a Key object for key buffer for SESSION key
 *
 * \param container A memory allocated by the caller to accomodate the object
 * \return DX_KeyObjHandle_t The created object handle
 */
DX_KeyObjHandle_t DX_KeyObjCreateSessionKey(DX_KeyObjContainer_t container)
{
    KeyBuffer_s *newObj = (KeyBuffer_s *)container;

    newObj->cryptoKeyType = SEP_SESSION_KEY;
    newObj->pKey          = DX_NULL;
    newObj->keyPtrType    = KEY_BUF_NULL;
    return OBJ_TO_HANDLE(newObj);
}

/* !
 * Free resources of given KEY object.
 * This function must be invoked before freeing or reusing the object container
 *
 * \param objHandle The KEY object handle
 */
void DX_KeyObjDestroy(DX_KeyObjHandle_t objHandle)
{
    /* Nothing to do today - just a place holder */
}
