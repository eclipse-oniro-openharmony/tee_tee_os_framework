/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/



#ifndef _CC_PAL_DMA_H
#define _CC_PAL_DMA_H

/*!
@file
@brief This file contains definitions that are used for the DMA related APIs. The implementation of these functions
need to be replaced according to Platform and TEE_OS.
*/

#ifdef __cplusplus
extern "C"
{
#endif

#include "cc_pal_types.h"
#include "cc_pal_dma_plat.h"
#include "cc_pal_dma_defs.h"
#include "cc_general_defs.h"

/*! User buffer scatter information. */
typedef struct {
	CCDmaAddr_t		blockPhysAddr;
	uint32_t		blockSize;
}CCPalDmaBlockInfo_t;

#ifdef BIG__ENDIAN
#define  SET_WORD_LE(val) cpu_to_le32(val)
#else
#define  SET_WORD_LE
#endif

/**
 * @brief   This function is called by the ARM TrustZone CryptoCell TEE runtime library before the HW is used.
 *      It maps a given data buffer (virtual address) for ARM TrustZone CryptoCell TEE HW DMA use (physical address), and returns the list of
 *      one or more DMA-able (physical) blocks. It may lock the buffer for ARM TrustZone CryptoCell TEE HW use. Once it is called,
 *      only ARM TrustZone CryptoCell TEE HW access to the buffer is allowed, until it is unmapped.
 *      If the data buffer was already mapped by the Secure TEE_OS prior to calling the ARM TrustZone CryptoCell TEE runtime library,
 *      this API does not have to perform any actual mapping operation, but only return the list of DMA-able blocks.
 *
 * @return A non-zero value in case of failure.
 */
uint32_t CC_PalDmaBufferMap(uint8_t                	  *pDataBuffer, 	/*!< [in] Address of the buffer to map. */
			    uint32_t                      buffSize,		/*!< [in] Buffer size in bytes. */
			    CCPalDmaBufferDirection_t     copyDirection,	/*!< [in] Copy direction of the buffer, according to ::CCPalDmaBufferDirection_t,
											  <ul><li>TO_DEVICE - the original buffer is the input to the operation,
											  and this function should copy it to the temp buffer,
											  prior to the activating the HW on the temp buffer.</li>
											  <li>FROM_DEVICE - not relevant for this API.</li>
											  <li>BI_DIRECTION - used when the crypto operation is "in-place", meaning
											  the result of encryption or decryption is written over the original data
											  at the same address. Should be treated by this API same as
											  TO_DEVICE. </li></ul> */
			     uint32_t                     *pNumOfBlocks,	/*!< [in/out]  Maximum numOfBlocks to fill, as output the actual number. */
			     CCPalDmaBlockInfo_t          *pDmaBlockList,	/*!< [out] List of DMA-able blocks that the buffer maps to. */
			     CC_PalDmaBufferHandle         *dmaBuffHandle	/*!< [out] A handle to the mapped buffer private resources.*/ );


/**
 * @brief   This function is called by the ARM TrustZone CryptoCell TEE runtime library after the HW is used.
 *  	It unmaps a given buffer, and frees its associated resources, if needed. It may unlock the buffer and flush it for CPU use.
 *  	Once it is called, ARM TrustZone CryptoCell TEE HW does not require access to this buffer anymore.
 *  	If the data buffer was already mapped by the Secure TEE_OS prior to calling the ARM TrustZone CryptoCell TEE runtime library, this API does
 *  	not have to perform any un-mapping operation, and the actual un-mapping can be done by the Secure TEE_OS outside the context
 *  	of the ARM TrustZone CryptoCell TEE runtime library.
 * @return A non-zero value in case of failure.
 */
uint32_t CC_PalDmaBufferUnmap(uint8_t                	    *pDataBuffer,	/*!< [in] Address of the buffer to unmap. */
			      uint32_t                       buffSize,		/*!< [in] Buffer size in bytes. */
			      CCPalDmaBufferDirection_t      copyDirection,	/*!< [in] Copy direction of the buffer, according to ::CCPalDmaBufferDirection_t
											  <ul><li>TO_DEVICE - not relevant for this API. </li>
											  <li>FROM_DEVICE - the temp buffer holds the output of the HW, and this
											  API should copy it to the actual output buffer.</li>
											  <li>BI_DIRECTION - used when the crypto operation is "in-place", meaning
											  the result of encryption or decryption is written over the original data
											  at the same address. Should be treated by this API same as
											  FROM_DEVICE.</li></ul> */
			      uint32_t                       numOfBlocks,	        /*!< [in] Number of DMA-able blocks that the buffer maps to. */
			      CCPalDmaBlockInfo_t            *pDmaBlockList,	/*!< [in] List of DMA-able blocks that the buffer maps to. */
			      CC_PalDmaBufferHandle          dmaBuffHandle	/*!< [in] A handle to the mapped buffer private resources. */);


/**
 * @brief Allocates a DMA-contiguous buffer for CPU use, and returns its virtual address.
 * 	Before passing the buffer to the ARM TrustZone CryptoCell TEE HW, ::CC_PalDmaBufferMap should be called.
 * 	\note The returned address must be aligned to 32 bits.
 *
 *
 * @return A non-zero value in case of failure.
 */
uint32_t CC_PalDmaContigBufferAllocate(uint32_t          buffSize, /*!< [in] Buffer size in bytes.*/
				       uint8_t           **ppVirtBuffAddr /*!< [out]  Virtual address of the allocated buffer.*/);



/**
 * @brief Frees resources previously allocated by ::CC_PalDmaContigBufferAllocate.
 *
 *
 * @return A non-zero value in case of failure.
 */
uint32_t CC_PalDmaContigBufferFree(uint32_t          buffSize, /*!< [in] Buffer size in Bytes. */
				   uint8_t           *pVirtBuffAddr /*!< [in] Virtual address of the buffer to free. */);



/**
 * @brief Checks whether the buffer is guaranteed to be a single contiguous DMA block.
 *
 *
 * @return TRUE if the buffer is guaranteed to be a single contiguous DMA block, and FALSE otherwise.
 */
uint32_t CC_PalIsDmaBufferContiguous(uint8_t                	 *pDataBuffer, /*!< [in] User buffer address. */
				     uint32_t                    buffSize   /*!< [in] User buffer size. */);


#ifdef __cplusplus
}
#endif

#endif


