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

#ifndef CC_PLAT_H
#define CC_PLAT_H

/*
 * Address types within CC
 */
typedef uint32_t DxSramAddr_t;
typedef uint64_t DxDmaAddr_t;

// add by fugengsheng, 2014/12/24
#include "dx_pal_types_plat.h"

#define NULL_SRAM_ADDR ((DxSramAddr_t)0xFFFFFFFF)

#define CURR_TASK_ID()         (0) /* single task -single queue */
#define CURR_QUEUE_ID()        CURR_TASK_ID()
#define IS_SCHEDULER_RUNNING() (1) /* in signle task application always busy */

/* *************************************************************** */
/* *************************************************************** */
/* The below MACROS are used by the driver to access the context. */
/* Since the context is in the SRAM it must use indirect access to */
/* the CC internal SRAM.                                          */
/* *************************************************************** */
/* *************************************************************** */
#define _WriteWordsToSram(addr, data, size)                                                                    \
    do {                                                                                                       \
        uint32_t ii;                                                                                           \
        volatile uint32_t dummy;                                                                               \
        DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(HOST_RGF, SRAM_ADDR), (addr));                                 \
        for (ii = 0; ii < size / sizeof(uint32_t); ii++) {                                                     \
            DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(HOST_RGF, SRAM_DATA), SWAP_TO_LE(((uint32_t *)data)[ii])); \
            do {                                                                                               \
                dummy = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, SRAM_DATA_READY));                    \
            } while (!(dummy & 0x1));                                                                          \
        }                                                                                                      \
    } while (0)

#define _ClearSram(addr, size)                                                              \
    do {                                                                                    \
        uint32_t ii;                                                                        \
        volatile uint32_t dummy;                                                            \
        DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(HOST_RGF, SRAM_ADDR), (addr));              \
        for (ii = 0; ii < size / sizeof(uint32_t); ii++) {                                  \
            DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(HOST_RGF, SRAM_DATA), 0);               \
            do {                                                                            \
                dummy = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, SRAM_DATA_READY)); \
            } while (!(dummy & 0x1));                                                       \
        }                                                                                   \
    } while (0)

#define _ReadValueFromSram(addr, Val)                                                   \
    do {                                                                                \
        volatile uint32_t dummy;                                                        \
        DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(HOST_RGF, SRAM_ADDR), (addr));          \
        dummy = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, SRAM_DATA));           \
        do {                                                                            \
            dummy = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, SRAM_DATA_READY)); \
        } while (!(dummy & 0x1));                                                       \
        dummy = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, SRAM_DATA));           \
        (Val) = SWAP_TO_LE(dummy);                                                      \
    } while (0)

#define _ReadWordsFromSram(addr, data, size)                                                       \
    do {                                                                                           \
        uint32_t ii;                                                                               \
        volatile uint32_t dummy;                                                                   \
        DX_HAL_WriteCcRegister(DX_CC_REG_OFFSET(HOST_RGF, SRAM_ADDR), (addr));                     \
        dummy = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, SRAM_DATA));                      \
        for (ii = 0; ii < size / sizeof(uint32_t); ii++) {                                         \
            do {                                                                                   \
                dummy = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, SRAM_DATA_READY));        \
            } while (!(dummy & 0x1));                                                              \
            dummy                  = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, SRAM_DATA)); \
            ((uint32_t *)data)[ii] = SWAP_TO_LE(dummy);                                            \
        }                                                                                          \
        do {                                                                                       \
            dummy = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, SRAM_DATA_READY));            \
        } while (!(dummy & 0x1));                                                                  \
    } while (0)

/* ************************************************************************************* */
/*
 *
 * @brief The function gets one word from the context.
 *
 *
 * @param[in] addr - The address of the word ( pointer to a word in the context).
 *
 * @return uint32_t - The value of that address.
 */
uint32_t ReadContextWord(const DxSramAddr_t addr);

/* ************************************************************************************* */
/*
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

/* ************************************************************************************* */
/*
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

/* ************************************************************************************* */
/*
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

/* ************************************************************************************* */
/*
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
