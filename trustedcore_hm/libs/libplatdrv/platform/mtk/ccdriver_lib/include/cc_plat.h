/****************************************************************************
* This confidential and proprietary software may be used only as authorized *
* by a licensing agreement from ARM Israel.                                 *
* Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
* The entire notice above must be reproduced on all authorized copies and   *
* copies may only be made to the extent permitted by a licensing agreement  *
* from ARM Israel.                                                          *
*****************************************************************************/

#ifndef  CC_PLAT_H
#define  CC_PLAT_H

#include "ssi_pal_types.h"

#ifndef CMPU_UTIL
#include "ssi_pal_mutex.h"
#include "ssi_pal_abort.h"

extern SaSi_PalMutex sasiSymCryptoMutex;
#endif

/**
 * Address types within CC
 */
typedef uint32_t DxSramAddr_t;
typedef uint64_t SaSiDmaAddr_t;

#define NULL_SRAM_ADDR ((DxSramAddr_t)0xFFFFFFFF)

#define CURR_TASK_ID() (0) /*single task -single queue*/
#define CURR_QUEUE_ID() CURR_TASK_ID()
#define IS_SCHEDULER_RUNNING() (1) /*in signle task application always busy*/


/******************************************************************/
/******************************************************************/
/* The below MACROS are used by the driver to access the context. */
/* Since the context is in the SRAM it must use indirect access to*/
/* the ARM TrustZone CryptoCell internal SRAM.                                          */
/******************************************************************/
/******************************************************************/
#define _WriteWordsToSram(addr, data, size) \
do { \
	uint32_t ii; \
	volatile uint32_t dummy; \
	SASI_HAL_WRITE_REGISTER( SASI_REG_OFFSET (HOST_RGF,SRAM_ADDR), (addr)); \
	for( ii = 0 ; ii < size/sizeof(uint32_t) ; ii++ ) { \
		   SASI_HAL_WRITE_REGISTER( SASI_REG_OFFSET (HOST_RGF,SRAM_DATA), SWAP_TO_LE(((uint32_t *)data)[ii])); \
		   do { \
		     dummy = SASI_HAL_READ_REGISTER( SASI_REG_OFFSET (HOST_RGF, SRAM_DATA_READY)); \
		   }while(!(dummy & 0x1)); \
	} \
}while(0)  



#define _ClearSram(addr, size) \
do { \
	uint32_t ii; \
	volatile uint32_t dummy; \
	SASI_HAL_WRITE_REGISTER( SASI_REG_OFFSET(HOST_RGF, SRAM_ADDR), (addr) ); \
	for( ii = 0 ; ii < size/sizeof(uint32_t) ; ii++ ) { \
		SASI_HAL_WRITE_REGISTER( SASI_REG_OFFSET (HOST_RGF,SRAM_DATA), 0 ); \
		do { \
			dummy = SASI_HAL_READ_REGISTER( SASI_REG_OFFSET(HOST_RGF, SRAM_DATA_READY)); \
		}while(!(dummy & 0x1)); \
	}\
}while(0)


#define _ReadValueFromSram(addr, Val) \
do { \
	volatile uint32_t dummy; \
	SASI_HAL_WRITE_REGISTER( SASI_REG_OFFSET (HOST_RGF,SRAM_ADDR), (addr) ); \
	dummy = SASI_HAL_READ_REGISTER( SASI_REG_OFFSET (HOST_RGF,SRAM_DATA)); \
	do { \
		dummy = SASI_HAL_READ_REGISTER( SASI_REG_OFFSET (HOST_RGF, SRAM_DATA_READY)); \
	}while(!(dummy & 0x1)); \
	dummy = SASI_HAL_READ_REGISTER( SASI_REG_OFFSET (HOST_RGF,SRAM_DATA)); \
	(Val) = SWAP_TO_LE(dummy);\
	do { \
		dummy = SASI_HAL_READ_REGISTER( SASI_REG_OFFSET (HOST_RGF, SRAM_DATA_READY) ); \
	}while(!(dummy & 0x1)); \
}while(0)   


#define _ReadWordsFromSram( addr , data , size ) \
do { \
	uint32_t ii; \
	volatile uint32_t dummy; \
	SASI_HAL_WRITE_REGISTER( SASI_REG_OFFSET (HOST_RGF,SRAM_ADDR) ,(addr) ); \
	dummy = SASI_HAL_READ_REGISTER( SASI_REG_OFFSET (HOST_RGF,SRAM_DATA)); \
	for( ii = 0 ; ii < size/sizeof(uint32_t) ; ii++ ) { \
		do { \
			dummy = SASI_HAL_READ_REGISTER( SASI_REG_OFFSET (HOST_RGF, SRAM_DATA_READY)); \
		}while(!(dummy & 0x1)); \
		dummy = SASI_HAL_READ_REGISTER( SASI_REG_OFFSET (HOST_RGF,SRAM_DATA));\
		((uint32_t*)data)[ii] = SWAP_TO_LE(dummy); \
	} \
	do { \
		dummy = SASI_HAL_READ_REGISTER( SASI_REG_OFFSET (HOST_RGF, SRAM_DATA_READY)); \
	}while(!(dummy & 0x1)); \
}while(0)   


#ifndef CMPU_UTIL
#define CLEAR_TRNG_SRC() {\
	if (SaSi_PalMutexLock(&sasiSymCryptoMutex, SASI_INFINITE) != SASI_SUCCESS) {\
		SaSi_PalAbort("Fail to acquire mutex\n");\
	}\
	 _ClearSram(SASI_SRAM_RND_HW_DMA_ADDRESS, SASI_SRAM_RND_MAX_SIZE);\
	if(SaSi_PalMutexUnlock(&sasiSymCryptoMutex) != SASI_SUCCESS) {\
		SaSi_PalAbort("Fail to release mutex\n");\
	}\
}
#else
#define CLEAR_TRNG_SRC()  _ClearSram(SASI_SRAM_RND_HW_DMA_ADDRESS, SASI_SRAM_RND_MAX_SIZE)
#endif
/****************************************************************************************/
/**
 * 
 * @brief The function gets one word from the context.
 * 
 * 
 * @param[in] addr - The address of the word ( pointer to a word in the context).
 *
 * @return uint32_t - The value of that address.  
 */
uint32_t ReadContextWord(const DxSramAddr_t addr);


/****************************************************************************************/
/**
 * 
 * @brief The function writes one word to the context.
 * 
 * 
 * @param[in] addr - The address of the word ( pointer to a word in the context).
 *
 * @param[in] data - The vaule to be written.
 *
 * @return void.
 */
void WriteContextWord(DxSramAddr_t addr, uint32_t data);

/****************************************************************************************/
/**
 * 
 * @brief The function clears field in the context.
 * 
 * 
 * @param[in] addr - The address of the field ( pointer to the field in the context).
 *
 * @param[in] size - The size of the field in bytes.
 *
 * @return void.
 */
void ClearCtxField(DxSramAddr_t addr, uint32_t size);

/****************************************************************************************/
/**
 * 
 * @brief The function update array field in the context (more than one word).
 * 
 * 
 * @param[in] addr - The address of the field ( pointer to the field in the context).
 *
 * @param[in] data - The data to write to the field.
 *
 * @param[in] size - The size of the field in bytes.
 *
 * @return void.
 */
void WriteContextField(DxSramAddr_t addr, const uint32_t *data, uint32_t size);

/****************************************************************************************/
/**
 * 
 * @brief The function reads array field in the context (more than one word).
 * 
 * 
 * @param[in] addr - The address of the field ( pointer to the field in the context).
 *
 * @param[in] data - buffer to read the data into.
 *
 * @param[in] size - The size of the field in bytes.
 *
 * @return void.
 */
void ReadContextField(const DxSramAddr_t addr, const uint32_t *data, uint32_t size);
#endif
