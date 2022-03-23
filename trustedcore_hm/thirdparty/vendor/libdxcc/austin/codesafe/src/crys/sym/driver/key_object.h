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

#ifndef __KEY_OBJECT_H__
#define __KEY_OBJECT_H__
/*
 * This header file defines the API for the Key object.
 */

/* Object container size */
#define DX_KEY_OBJ_CONTAINER_SIZE       12
#define DX_KEY_OBJ_CONTAINER_SIZE_WORDS (DX_KEY_OBJ_CONTAINER_SIZE >> 2)

/* The Key object handle */
typedef uint32_t DX_KeyObjHandle_t;
#define DX_KEY_OBJ_INVALID_HANDLE 0

/* The Key object container - to be allocated by caller */
typedef uint32_t DX_KeyObjContainer_t[DX_KEY_OBJ_CONTAINER_SIZE_WORDS];

/* !
 * Create a Key object for key buffer for user key in SRAM
 *
 * \param container A memory allocated by the caller to accomodate the object
 * \param aKeyAddr user key pointer
 * \return DX_KeyObjHandle_t The created object handle
 */
DX_KeyObjHandle_t DX_KeyObjCreateSepUserKey(DX_KeyObjContainer_t container, uint32_t aKeyAddr);

/* !
 * Create a Key object for key buffer for user key in HOST
 *
 * \param container A memory allocated by the caller to accomodate the object
 * \param aKeyAddr user key pointer
 * \return DX_KeyObjHandle_t The created object handle
 */
DX_KeyObjHandle_t DX_KeyObjCreateHostUserKey(DX_KeyObjContainer_t container, uint32_t aKeyAddr);

/* !
 * Create a Key object for key buffer for ROOT key
 *
 * \param container A memory allocated by the caller to accomodate the object
 * \return DX_KeyObjHandle_t The created object handle
 */
DX_KeyObjHandle_t DX_KeyObjCreateRkekKey(DX_KeyObjContainer_t container);

/* !
 * Create a Key object for key buffer for APPLET key
 *
 * \param container A memory allocated by the caller to accomodate the object
 * \return DX_KeyObjHandle_t The created object handle
 */
DX_KeyObjHandle_t DX_KeyObjCreateAppletKey(DX_KeyObjContainer_t container);

/* !
 * Create a Key object for key buffer for Provisioning key
 *
 * \param container A memory allocated by the caller to accomodate the object
 * \return DX_KeyObjHandle_t The created object handle
 */
DX_KeyObjHandle_t DX_KeyObjCreateProvKey(DX_KeyObjContainer_t container);

/* !
 * Free resources of given KEY object.
 * This function must be invoked before freeing or reusing the object container
 *
 * \param objHandle The KEY object handle
 */
void DX_KeyObjDestroy(DX_KeyObjHandle_t objHandle);

#endif /* __KEY_OBJECT_H__ */
