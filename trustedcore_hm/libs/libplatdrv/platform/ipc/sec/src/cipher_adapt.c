/*****************************************************************************

    Copyright (C), 2017, Hisilicon Tech. Co., Ltd.

******************************************************************************
  File Name     : cipher_adapt.c
  Version       : Initial Draft
  Created       : 2017
  Last Modified :
  Description   :
  Function List :
  History       :
******************************************************************************/

#include "cipher_adapt.h"
/************************* SYSTEM API ************************/
void *crypto_memcpy(void *dst, unsigned dstlen, const void *src, unsigned len)
{
    if ((dst == NULL) || (src == NULL) || (dstlen < len)) {
        HI_ERR_CIPHER("Error: cipher call %s with invalid parameter.\n", __FUNCTION__);
        return NULL;
    }

    return memcpy(dst, src, len);
}

void *crypto_memset(void *dst, unsigned int dlen, unsigned val, unsigned int len)
{
    if ((dst == NULL) || (dlen < len)) {
        HI_ERR_CIPHER("Error: cipher call %s with invalid parameter.\n", __FUNCTION__);
        return NULL;
    }

    return memset(dst, val, len);
}

int crypto_memcmp(const void *a, const void *b, unsigned int len)
{
    if ((a == NULL) || (b == NULL)) {
        HI_ERR_CIPHER("Error: cipher call %s with invalid parameter, point is null.\n", __FUNCTION__);
        return HI_FAILURE;
    }

    if (a == b) {
        HI_ERR_CIPHER("Error: cipher call %s with invalid parameter, comparing with the same address.\n", __FUNCTION__);
        return HI_FAILURE;
    }

    return memcmp(a, b, len);
}

void HEX2STR(char buf[2], HI_U8 val)
{
    HI_U8 high, low;

    high = (val >> 4) & 0x0F;
    low =  val & 0x0F;

    if(high <= 9)
    {
        buf[0] = high + '0';
    }
    else
    {
        buf[0] = (high - 0x0A) + 'A';
    }

    if(low <= 9)
    {
        buf[1] = low + '0';
    }
    else
    {
        buf[1] = (low - 0x0A) + 'A';
    }

}

void PrintData(const char*pbName, HI_U8 *pbData, HI_U32 u32Size)
{
    HI_U32 i;
    char buf[2];

    if (pbName != HI_NULL)
    {
        HI_PRINT("[%s-%p]:\n", pbName, pbData);
    }
    for (i=0; i<u32Size; i++)
    {
        HEX2STR(buf, pbData[i]);
        HI_PRINT("%c%c ", buf[0], buf[1]);
        if(((i+1) % 16) == 0)
            HI_PRINT("\n");
    }
    if (( i % 16) != 0)
    {
        HI_PRINT("\n");
    }
}

