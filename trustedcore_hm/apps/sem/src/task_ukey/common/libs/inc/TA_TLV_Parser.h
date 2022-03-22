#ifndef TA_TLV_PARSER_H
#define TA_TLV_PARSER_H

#include <stddef.h>
#include <TA_Parcel.h>
#include <tee_mem_mgmt_api.h>
#include <tee_internal_api.h>
#include "libhwsecurec/securec.h"

#define USE_DEFAULT_TAG     0xFFFF
#define TLV_FAIL -1

typedef struct _tlv_base {
	unsigned short tag;
	unsigned short length;
	unsigned short check_tag;
	unsigned short has_value;
	int32_t (*parse)(struct _tlv_base *, ta_parcel_t *);
	int32_t (*getlen)(struct _tlv_base *);
	int32_t (*encode)(struct _tlv_base *, ta_parcel_t *);
	void (*deinit)(struct _tlv_base *);
} tlv_base;


///////////////////////////////////////////////////////////////////
//// TLV STRUCT 声明宏
//// 通过该宏声明一个TLV STRUCT类型
#define DECLARE_TLV_STRUCT(x)   \
    tlv_base base;  \
    unsigned int offset_count; \
    unsigned int offset[x];

unsigned short get_tag(unsigned short check_tag, unsigned short default_tag);

///////////////////////////////////////////////////////////////////
//// TLV STRUCT INIT函数定义宏组
//// 该宏组由BEGIN_TLV_STRUCT_DEFINE, TLV_MEMBER, END_TLV_STRUCT_DEFINE三个宏组成
//// 拼凑出一个完整的init和函数
#define BEGIN_TLV_STRUCT_DEFINE(TLV_S, CHECK_TAG)  \
void deinit_##TLV_S(TLV_S* tlv)  \
{ \
    tlv_base* tlv_b = (tlv_base*)tlv; \
    tlv_b->deinit(tlv_b); \
} \
void init_##TLV_S(TLV_S* tlv, unsigned short check_tag)       \
{   \
    typedef TLV_S tlv_s_type;  \
    unsigned int index = 0;    \
    (void)memset_s(&tlv->base, sizeof(tlv->base), 0, sizeof(tlv->base));    \
    tlv->base.check_tag = get_tag(check_tag, CHECK_TAG);


#define TLV_MEMBER(TLV_M, TLV_M_NAME, CHECK_TAG)   \
    init_##TLV_M(&tlv->TLV_M_NAME, CHECK_TAG);    \
    tlv->offset[index++] = offsetof(tlv_s_type, TLV_M_NAME);

#define END_TLV_STRUCT_DEFINE()         \
    tlv->offset_count = index;          \
    tlv->base.parse = parse_tlv_struct;   \
    tlv->base.getlen = getlen_tlv_struct;   \
    tlv->base.encode = encode_tlv_struct;   \
    tlv->base.deinit = deinit_tlv_struct;   \
}


///////////////////////////////////////////////////////////////////
//// 固定长度结构体声明宏
//// 通过该宏声明一个固定长度结构体类型
//// 该宏应该放置在.h中，并配合.c中的【固定长度结构体定义宏】使用
#define DECLARE_TLV_FIX_LENGTH_TYPE(TLV_NAME, TYPE_NAME)  \
typedef struct  \
{   \
    tlv_base base;  \
    TYPE_NAME data;  \
} TLV_NAME;

////////////////////////////////basic types
DECLARE_TLV_FIX_LENGTH_TYPE(tlv_int32, int)
DECLARE_TLV_FIX_LENGTH_TYPE(tlv_int16, short)
DECLARE_TLV_FIX_LENGTH_TYPE(tlv_int8, char)
DECLARE_TLV_FIX_LENGTH_TYPE(tlv_uint32, uint32_t)
DECLARE_TLV_FIX_LENGTH_TYPE(tlv_uint16, uint16_t)
DECLARE_TLV_FIX_LENGTH_TYPE(tlv_uint8, uint8_t)
DECLARE_TLV_FIX_LENGTH_TYPE(tlv_uint64, uint64_t)
DECLARE_TLV_FIX_LENGTH_TYPE(tlv_int64, uint64_t)
///////////////////////////////////////////////////////////////////
//// 固定长度结构体定义宏
//// 通过该定义宏定义一个固定长度结构体类型
//// 该宏应该放置在.c中，并配合.h中的【固定长度结构体声明宏】使用
#define DEFINE_TLV_FIX_LENGTH_TYPE(TLV_NAME, REVERT)  \
int32_t parse_tlv_##TLV_NAME(tlv_base* tlv, ta_parcel_t* parcel) \
{   \
    TLV_NAME* real_tlv = (TLV_NAME*)(tlv);  \
    TA_BOOL readRet = TA_FALSE; \
    if(tlv->length != sizeof(real_tlv->data))   \
    {   \
        return TLV_FAIL;   \
    }   \
        \
    if(REVERT)  \
    {   \
        readRet = parcel_read_revert(parcel, &real_tlv->data, sizeof(real_tlv->data));  \
    }   \
    else \
    { \
        readRet = parcel_read(parcel, &real_tlv->data, sizeof(real_tlv->data)); \
    }   \
    if(readRet)    \
    {   \
        return tlv->length; \
    }   \
    else    \
    {   \
        return TLV_FAIL;   \
    }   \
}   \
\
int32_t getlen_tlv_##TLV_NAME(tlv_base* tlv)   \
{	\
    TLV_NAME* real_tlv = (TLV_NAME*)(tlv);  \
    return (int32_t)sizeof(real_tlv->data); \
}   \
int32_t encode_tlv_##TLV_NAME(tlv_base* tlv, ta_parcel_t* parcel)   \
{ \
    TA_BOOL writeRet = TA_FALSE; \
    TLV_NAME* real_tlv = (TLV_NAME*)(tlv);  \
    if(REVERT) \
    { \
        writeRet = parcel_write_revert(parcel, &real_tlv->data, sizeof(real_tlv->data)); \
    } \
    else \
    { \
        writeRet = parcel_write(parcel, &real_tlv->data, sizeof(real_tlv->data)); \
    } \
    if(writeRet)   \
    {   \
        return sizeof(real_tlv->data);  \
    }   \
    else \
    {   \
        return TLV_FAIL;   \
    }   \
}   \
void deinit_tlv_##TLV_NAME(tlv_base* tlv)   \
{ \
    tlv = tlv; \
}   \
\
DECLARE_TLV_PARSE_FUNC(TLV_NAME, parse_tlv_##TLV_NAME, getlen_tlv_##TLV_NAME, encode_tlv_##TLV_NAME,deinit_tlv_##TLV_NAME);

///////////////////////////////////////////////////////////////////
//// TLV INIT函数宏
//// 通过该宏创建出一个TLV数据类型的INIT函数
#define DECLARE_TLV_PARSE_FUNC(TLV_NAME, TLV_PARSE_FUNC, TLV_GETLEN_FUNC, TLV_ENCODE_FUNC,TLV_DEINIT_FUNC)    \
void init_##TLV_NAME(TLV_NAME* tlv, unsigned short check_tag) \
{   \
    (void)memset_s(&tlv->base, sizeof(tlv->base), 0, sizeof(tlv->base));    \
    tlv->base.parse = TLV_PARSE_FUNC;   \
    tlv->base.getlen = TLV_GETLEN_FUNC; \
    tlv->base.encode = TLV_ENCODE_FUNC; \
    tlv->base.deinit = TLV_DEINIT_FUNC; \
    tlv->base.check_tag = check_tag;    \
}

/////////////////////////////////////////////////////////////////////
//// init函数调用宏，通过该宏调用并初始化一个TLV STRUCT
#define TLV_INIT(TLV_NAME, TLV_DATA) init_##TLV_NAME(TLV_DATA, USE_DEFAULT_TAG);


/////////////////////////////////////////////////////////////////////
//// deinit函数调用宏，通过该宏销毁TLV STRUCT 动态分配的内存空间
#define TLV_DEINIT(TLV_DATA)  TLV_DATA.base.deinit((tlv_base* )(&TLV_DATA));


typedef struct {
	tlv_base base;
	unsigned int offset_count;
	unsigned int offset[0];
} tlv_offset_example;

TA_BOOL parse_tlv_head(tlv_base *tlv, ta_parcel_t *parcel);
int32_t parse_tlv_node(tlv_base *tlv, ta_parcel_t *parcel);
int32_t getlen_tlv_node(tlv_base *tlv);
void deinit_tlv_node(tlv_base *tlv);

int32_t parse_tlv_struct(tlv_base *tlv, ta_parcel_t *parcel);
int32_t encode_tlv_struct(tlv_base *tlv, ta_parcel_t *parcel);
int32_t getlen_tlv_struct(tlv_base *tlv);
void deinit_tlv_struct(tlv_base *tlv);

TA_BOOL decode_tlv_message(tlv_base *msg, ta_parcel_t *parcel);
TA_BOOL encode_tlv_message(tlv_base *msg, ta_parcel_t *parcel);

////////////////////////////////////////////////
// 不固定长度数据
typedef struct _tlv_buffer {
	tlv_base base;
	ta_parcel_t data;
} tlv_buffer;

int32_t parse_tlv_buffer(tlv_base *tlv, ta_parcel_t *parcel);
void init_tlv_buffer(tlv_buffer *tlv, unsigned short check_tag);
void deinit_tlv_buffer(tlv_base *tlv);

#define DECLEAR_INIT_FUNC(TLV_S) \
void init_##TLV_S(TLV_S* tlv, unsigned short check_tag);

DECLEAR_INIT_FUNC(tlv_uint64)
DECLEAR_INIT_FUNC(tlv_uint32)
DECLEAR_INIT_FUNC(tlv_uint16)
#endif
