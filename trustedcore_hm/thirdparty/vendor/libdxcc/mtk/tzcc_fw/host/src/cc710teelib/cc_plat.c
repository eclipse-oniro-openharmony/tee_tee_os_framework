/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#include "ssi_pal_types.h"
#include "ssi_pal_log.h"
#include "sns_silib.h"
#include "ssi_hal.h"
#include "cc_plat.h"
#include "ssi_regs.h"

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
uint32_t ReadContextWord(const DxSramAddr_t addr)
{
    uint32_t val;
    _ReadValueFromSram(addr, val);
    return val;
}

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
void WriteContextWord(DxSramAddr_t addr, uint32_t data)
{
    _WriteWordsToSram(addr, &data, 4);
}

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
void ClearCtxField(DxSramAddr_t addr, uint32_t size)
{
    _ClearSram(addr, size);
}

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
void ReadContextField(const DxSramAddr_t addr, const uint32_t *buff, uint32_t size)
{
    _ReadWordsFromSram(addr, buff, size);
}

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
void WriteContextField(DxSramAddr_t addr, const uint32_t *data, uint32_t size)
{
    _WriteWordsToSram(addr, data, size);
}
