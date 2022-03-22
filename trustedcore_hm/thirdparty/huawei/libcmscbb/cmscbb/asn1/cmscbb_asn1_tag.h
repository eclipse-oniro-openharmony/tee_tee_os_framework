/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#ifndef H_CMSCBB_ASN1_TAG_H
#define H_CMSCBB_ASN1_TAG_H

#ifndef CMSCBB_TAG_CLASS_MASK
#define CMSCBB_TAG_CLASS_MASK 0xC0
#endif
#ifndef CMSCBB_TAG_PC_MASK
#define CMSCBB_TAG_PC_MASK 0x20
#endif
#ifndef CMSCBB_TAG_CODE_MASK
#define CMSCBB_TAG_CODE_MASK 0x1F
#endif
#ifndef CMSCBB_LEN_MASK
#define CMSCBB_LEN_MASK 0x7F
#endif

/* CMSCBB_BER_CLASS */
typedef enum CmscbbBerClassEm {
    CBC_ANY_CLASS = -2,
    CBC_NULL_CLASS = -1,
    CBC_UNIV = 0,
    CBC_APPL = 1,
    CBC_CNTX = 2,
    CBC_PRIV = 3
} CMSCBB_BER_CLASS;

/* CMSCBB_BER_FORM */
typedef enum CmscbbBerFormEm {
    CBF_ANY_FORM = -2,
    CBF_NULL_FORM = -1,
    CBF_PRIM = 0,
    CBF_CONS = 1
} CMSCBB_BER_FORM;

/* CMSCBB_BER_TAG_CODE */
typedef enum CmscbbBerTagCodeEm {
    CBT_ANY_CODE = 100,
    CBT_NULL_CODE = 101,
    CBT_EOC = 0,
    CBT_BOOLEAN = 1,
    CBT_INTEGER = 2,
    CBT_BITSTRING = 3,
    CBT_OCTETSTRING = 4,
    CBT_NULLTYPE = 5,
    CBT_OID = 6,
    CBT_OBJECTDESCRIPTOR = 7,
    CBT_EXTERNAL = 8,
    CBT_REAL = 9,
    CBT_ENUM = 10,
    CBT_EMBEDDEDPDV = 11,
    CBT_UTF8STRING = 12,
    CBT_RELATIVE_OID = 13,
    CBT_RESERVED1 = 14,
    CBT_RESERVED2 = 15,
    CBT_SEQUENCES = 16,
    CBT_SETS = 17,
    CBT_NUMERICSTRING = 18,
    CBT_PRINTABLESTRING = 19,
    CBT_TELETEXSTRING = 20,
    CBT_VIDEOTEXSTRING = 21,
    CBT_IA5STRING = 22,
    CBT_UTCTIME = 23,
    CBT_GENERALIZEDTIME = 24,
    CBT_GRAPHICSTRING = 25,
    CBT_VISIBLESTRING = 26,
    CBT_GENERALSTRING = 27,
    CBT_UNIVERSALSTRING = 28,
    CBT_CHARACTERSTRING = 29,
    CBT_BMPSTRING_TAG_CODE = 30,
    CBT_LONG_FORM = 31
} CMSCBB_BER_TAG_CODE;

/* CMSCBB_BER_TAG */
typedef struct cmscbb_ber_tag_st {
    CMSCBB_BER_CLASS cls;
    CMSCBB_BER_FORM form;
    CMSCBB_BER_TAG_CODE code;
} CMSCBB_BER_TAG;
#define CVB_BER_TAG_INIT { CBC_NULL_CLASS, CBF_NULL_FORM, CBT_NULL_CODE }

#endif /* H_CMSCBB_ASN1_TAG_H */
