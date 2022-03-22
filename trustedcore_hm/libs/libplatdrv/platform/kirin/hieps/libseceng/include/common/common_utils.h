/**
 * @file   : common_utils.h
 * @brief  : general small tools
 * @par    : Copyright(c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2017/12/20
 */
#ifndef __COMMON_UTILS_H__
#define __COMMON_UTILS_H__
#include <pal_types.h>

#ifndef OBJECT
#define OBJECT(obj)   obj
#endif /* OBJECT */

#ifndef PRIVATE
#define PRIVATE static
#endif /* PRIVATE */

#ifndef STUB_FUNC
#define STUB_FUNC           __attribute__((weak)) /**< declare for stub function */
#endif /* STUB_FUNC */

#ifndef STATIC_INLINE
#define STATIC_INLINE OBJECT(static __attribute__((always_inline)) inline)
#endif /* STATIC_INLINE */

#ifndef ALIGN_U32
#define ALIGN_U32          __attribute__((aligned(sizeof(u32))))
#endif /* ALIGN_U32 */

#ifndef UNUSED
#define UNUSED(x)    ((void)(x))
#endif /* UNUSED */

/**< do nothing */
#ifndef DO_NOTHING
#define DO_NOTHING() do { } while (0)
#endif /* DO_NOTHING */

/**< array size */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)       (sizeof(x) / sizeof(x[0]))
#endif /* ARRAY_SIZE */

/**< convert to pointer type  */
#ifndef PTR
#define PTR(p)                  ((void *)(uintptr_t)(p))
#endif /* PTR */

#ifndef INTEGER
#define INTEGER(p)             ((uintptr_t)(p))
#endif /* INTEGER */

#ifndef ADDR_IS_CROSS
#define ADDR_IS_CROSS(pa, alen, pb, blen) \
	(((INTEGER(pa) > INTEGER(pb)) && (INTEGER(pa) < INTEGER(pb) + blen)) || \
	((INTEGER(pb) > INTEGER(pa)) && (INTEGER(pb) < INTEGER(pa) + alen)))
#endif /* ADDR_IS_CROSS */

/**< register attribute */
#ifndef REG_ATT
#define REG_ATT(p, type, member)    (((type *)(p))->reg.member)
#endif /* REG_ATT */

/******************* bit operation **************************/
#ifndef BITS_PER_BYTE
#define BITS_PER_BYTE           (8) /**< 8 bits per bytes */
#endif /* BITS_PER_BYTE */

/**< bit set to 1 */
#ifndef BIT_SET
#define BIT_SET(flag, bit)      do { flag |= (1U << (bit)); } while (0)
#endif /* BIT_SET */

/**< bit clear to 0 */
#ifndef BIT_CLS
#define BIT_CLS(flag, bit)      do { flag &= (~(1U << (bit))); } while (0)
#endif /* BIT_CLS */

/**< bit check */
#ifndef BIT_CHK
#define BIT_CHK(flag, bit)      ((flag) & (1U << (bit)))
#endif /* BIT_CHK */

/**< align to 2~bit */
#ifndef BIT_ALIGN
#define BIT_ALIGN(n, bit)       (((n) + ((1U << (bit)) - 1U)) & (~((1U << (bit)) - 1U)))
#endif /* BIT_ALIGN */

/**< modulo by 2~bit */
#ifndef BIT_MOD
#define BIT_MOD(n, bit)         ((n) & ((1U << (bit)) - 1U))
#endif /* BIT_MOD */

/**< modulo by 4 */
#ifndef WORD_MOD
#define WORD_MOD(n)              BIT_MOD(n, 2)
#endif /* WORD_MOD */

/**< bits to bytes */
#ifndef BIT2BYTE
#define BIT2BYTE(bits)          ((bits) >> 3)
#endif /* BIT2BYTE */

/**< bits to bytes, algin to a byte */
#ifndef BIT2BYTE_ALIGN
#define BIT2BYTE_ALIGN(bits)    BIT2BYTE(BIT_ALIGN(bits, 3))
#endif /* BIT2BYTE_ALIGN */

/**< bits to words */
#ifndef BIT2WORD
#define BIT2WORD(bits)          ((bits) >> (3 + 2))
#endif /* BIT2WORD */

/**< bytes to bita */
#ifndef BYTE2BIT
#define BYTE2BIT(bytes)         ((bytes) << 3)
#endif /* BYTE2BIT */

/**< bytes to words */
#ifndef BYTE2WORD
#define BYTE2WORD(bytes)        ((bytes) >> 2)
#endif /* BYTE2WORD */

/**< bytes to words, algin to a word */
#ifndef BYTE2WORD_ALIGN
#define BYTE2WORD_ALIGN(bytes)  BYTE2WORD(BIT_ALIGN(bytes, 2))
#endif /* BYTE2WORD_ALIGN */

/**< bytes to words */
#ifndef WORD2BYTE
#define WORD2BYTE(words)        ((words) << 2)
#endif /* WORD2BYTE */

/******************* math operation **************************/
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

/**< data interchange (bit algorithm to reduce stack ) */
#ifndef NUM_SWITCH
#define NUM_SWITCH(a, b) do {(a) = (a) ^ (b); (b) = (a) ^ (b); (a) = (a) ^ (b); } while (0)
#endif /* NUM_SWITCH */

/**< least significant bit of u8 */
#ifndef U8_LSB
#define U8_LSB(b)           ((b) & 0x0F)
#endif /* U8_LSB */
/**< most significant bit of u8 */
#ifndef U8_MSB
#define U8_MSB(b)          (((u8)(b)) >> (BITS_PER_BYTE >> 1))
#endif /* U8_MSB */

/**< least significant bit of u16 */
#ifndef U16_LSB
#define U16_LSB(s)          ((u8)(u16)(s))
#endif /* U16_LSB */
/**< most significant bit of u16 */
#ifndef U16_MSB
#define U16_MSB(s)          ((u8)((u16)(s) >> BITS_PER_BYTE))
#endif /* U16_MSB */

/**< least significant bit of u32 */
#ifndef U32_LSB
#define U32_LSB(n)          ((u16)(u32)(n))
#endif /* U32_LSB */
/**< ost significant bit of u32 */
#ifndef U32_MSB
#define U32_MSB(n)          ((u16)((u32)(n) >> (BITS_PER_BYTE << 1)))
#endif /* U32_MSB */

#ifndef U64_LSB
#define U64_LSB(n)          ((u32)(n))
#endif

#ifndef U64_MSB
#define U64_MSB(n)          ((u32)((n)>>32))
#endif

/**< make 2 u8 to a u16 */
#ifndef TOU16
#define TOU16(h_u8, l_u8)   (u16)(((u8)(h_u8) << BITS_PER_BYTE) | (u8)(l_u8))
#endif /* TOU16 */
/**< make 2 u16 to a u32 */
#ifndef TOU32
#define TOU32(h_u16, l_u16) (u32)(((u16)(h_u16) << 16) | (u16)(l_u16))
#endif /* TOU32 */

/**< make u16 reversal by byte */
#ifndef U16_REV
#define U16_REV(v)          TOU16(U16_LSB(v), U16_MSB(v))
#endif /* U16_REV */

/**< make u32 reversal by byte */
#ifndef U32_REV
#define U32_REV(v)  ((0 == (v)) ? 0 : (((u32)U16_REV(U32_LSB(v)) << 16) | U16_REV(U32_MSB(v))))
#endif /* U32_REV */

#ifndef U64_REV
#define U64_REV(v)  ((0 == (v)) ? 0 : (((u64)U32_REV(U64_LSB(v)) << 32) | U32_REV(U64_MSB(v))))
#endif /* U64_REV */

#ifndef ROUND_UP
#define ROUND_UP(num, base) ((0 == (base)) ? (num) : (((num) + (base) - 1) / (base) * (base)))
#endif /* ROUND_UP */

/******************* character operation **************************/
/* check if it is digit */
#ifndef ISDIGIT
#define ISDIGIT(c) (('0' <= (c)) && ((c) <= '9'))
#endif /* ISDIGIT */

#ifndef DIGIT2DEC
#define DIGIT2DEC(c) ((c) - '0')
#endif /* DIGIT2DEC */

/* check if it is lower case */
#ifndef ISLOWER
#define ISLOWER(c) (('a' <= (c)) && ((c) <= 'z'))
#endif /* ISLOWER */

/* check if it is upper case  */
#ifndef ISUPPER
#define ISUPPER(c) (('A' <= (c)) && ((c) <= 'Z'))
#endif /* ISUPPER */

/* covert to lower case */
#ifndef TOLOWER
#define TOLOWER(c) (char)(ISUPPER(c) ? (((c) - 'A') + 'a') : (c))
#endif /* TOLOWER */

/* covert to upper case */
#ifndef TOUPPER
#define TOUPPER(c) (char)(ISLOWER(c) ? (((c) - 'a') + 'A') : (c))
#endif /* TOUPPER */

/* covert to lower hexadecimal character */
#ifndef TOHEXL
#define TOHEXL(c) (char)(((c) < 10) ? ((c) + '0') : (((c) - 10) + 'a'))
#endif /* TOHEXL */

/* covert to upper hexadecimal character */
#ifndef TOHEXU
#define TOHEXU(c) (char)(((c) < 10) ? ((c) + '0') : (((c) - 10) + 'A'))
#endif /* TOHEXU */

/* check if character is valid */
#ifndef IS_VALID_CHAR
#define IS_VALID_CHAR(c) ((0x20 <= (c)) && ((c) <= 0x7E))
#endif /* IS_VALID_CHAR */

/* check if is hexadecimal character */
#ifndef ISHEX
#define ISHEX(c) (ISDIGIT(c) || ((('A' <= (c)) && ((c) <= 'F')) || (('a' <= (c)) && ((c) <= 'f'))))
#endif /* ISHEX */

/* covert hexadecimal character to decimal integer */
#ifndef HEX2BYTE
#define HEX2BYTE(c) (ISDIGIT(c) ? DIGIT2DEC(c) : (10 + (ISLOWER(c) ? ((c) - 'a') : ((c) - 'A'))))
#endif /* HEX2BYTE */

#endif /* end of __UTILS_H__ */
