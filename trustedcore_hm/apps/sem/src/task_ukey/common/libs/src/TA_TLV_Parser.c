#include "TA_TLV_Parser.h"
#include "TA_Log.h"
#include "libhwsecurec/securec.h"

#define NO_REVERT 0
#define NEED_REVERT 1
#define MAX_SHORT_VALUE 65535
#define MAX_INT_VALUE 0x7FFFFFFF

TA_BOOL parse_tlv_head(tlv_base *tlv, ta_parcel_t *parcel)
{
#ifdef IS_BIG_ENDIAN
    if (!parcel_read_uint16_revert(parcel, &tlv->tag)) {
        LOGE(" parse_tlv_head failed, read tag failed!!!");
        return TA_FALSE;
    }
#else
    if (!parcel_read_uint16(parcel, &tlv->tag)) {
        LOGE(" parse_tlv_head failed, read tag failed!!!");
        return TA_FALSE;
    }
#endif

    if (tlv->tag != tlv->check_tag) {
        LOGE(" parse_tlv_head failed, tag is error, expect:%x, get:%x!!!", tlv->check_tag, tlv->tag);
        return TA_FALSE;
    }
#ifdef IS_BIG_ENDIAN
    if (!parcel_read_uint16_revert(parcel, &tlv->length)) {
        LOGE(" parse_tlv_head failed, read length failed!!!");
        return TA_FALSE;
    }
#else
    if (!parcel_read_uint16(parcel, &tlv->length)) {
        LOGE(" parse_tlv_head failed, read length failed!!!");
        return TA_FALSE;
    }
#endif
    return TA_TRUE;
}

//���������������tlv�ڵ㣬����tlv�ڵ���ܳ���
int32_t parse_tlv_node(tlv_base *tlv, ta_parcel_t *parcel)
{
    //tlv ͷ����ʧ��
    if (!parse_tlv_head(tlv, parcel)) {
        return TLV_FAIL;
    } else {
        //�ж�parcel�����Ƿ��㹻
        if (get_parcel_data_size(parcel) < tlv->length) {
            //parcel����̫��
            LOGE("in function parse_tlv_node tlv->tag is:%x", tlv->tag);
            return TLV_FAIL;
        }

        //����tlv��body
        int ret = tlv->parse(tlv, parcel);
        if (ret < 0) {
            return ret;
        } else {
            //�����ɹ��������ܳ���
            return ret + sizeof(tlv->tag) + sizeof(tlv->length);
        }
    }
}

//�������������ȡtlv���ܳ���
int32_t getlen_tlv_node(tlv_base *tlv)
{
    //��ȡtlv��body����
    int32_t body_len = tlv->getlen(tlv);
    if (body_len < 0) {
        return TLV_FAIL;
    } else {
        if( (uint32_t)body_len > MAX_SHORT_VALUE - sizeof(tlv->tag) - sizeof(tlv->length))
        {
            return TLV_FAIL;
        }
        tlv->length = body_len + sizeof(tlv->tag) + sizeof(tlv->length);
        return (int32_t)tlv->length;
    }
}


void deinit_tlv_node(tlv_base *tlv)
{
    tlv->deinit(tlv);
}

//��������������tlv�ڵ����ݣ�����tlv�ڵ���ܳ���
int32_t encode_tlv_node(tlv_base *tlv, ta_parcel_t *parcel)
{
    //���Ȼ�ȡtlv body����
    int32_t body_len = tlv->getlen(tlv);
    if (body_len < 0) {
        return TLV_FAIL;
    } else if (body_len == 0) { //no value
        //body����Ϊ�գ�ֻ���tag��len
#ifdef IS_BIG_ENDIAN
        parcel_write_uint16_revert(parcel, tlv->check_tag);
        parcel_write_uint16_revert(parcel, body_len);
#else
        parcel_write_uint16(parcel, tlv->check_tag);
        parcel_write_uint16(parcel, body_len);
#endif
        return sizeof(tlv->tag) + sizeof(tlv->length);
    } else { //has value
        //��body�����tag, len������
        int32_t encode_len = 0;
        tlv->length = (uint16_t)body_len;
#ifdef IS_BIG_ENDIAN
        parcel_write_uint16_revert(parcel, tlv->check_tag);
        parcel_write_uint16_revert(parcel, tlv->length);
#else
        parcel_write_uint16(parcel, tlv->check_tag);
        parcel_write_uint16(parcel, tlv->length);
#endif
        encode_len = tlv->encode(tlv, parcel);
        if (encode_len < 0) {
            return TLV_FAIL;
        } else {
            return encode_len + sizeof(tlv->tag) + sizeof(tlv->length);
        }
    }
}

tlv_base *get_empty_struct_node(tlv_base *tlv, unsigned short tag)
{
    if (NULL == tlv) {
        return NULL;
    }

    unsigned int index = 0;
    unsigned int member_count = *(unsigned int *)((char *)tlv + offsetof(tlv_offset_example, offset_count));
    unsigned int *offset = (unsigned int *)((char *)tlv + offsetof(tlv_offset_example, offset));
    for (index = 0; index < member_count; ++index) {
        tlv_base *tlv_child = (tlv_base *)(((char *)tlv) + offset[index]);
        if (tlv_child->check_tag == tag && tlv_child->has_value == 0) {
            return tlv_child;
        }
    }

    return NULL;
}

int32_t check_struct_node_all_has_value(tlv_base *tlv)
{
    if (NULL == tlv) {
        return 0;
    } else {
        unsigned int index = 0;
        unsigned int member_count = *(unsigned int *)((char *)tlv + offsetof(tlv_offset_example, offset_count));
        unsigned int *offset = (unsigned int *)((char *)tlv + offsetof(tlv_offset_example, offset));
        for (index = 0; index < member_count; ++index) {
            tlv_base *tlv_child = (tlv_base *)(((char *)tlv) + offset[index]);
            if (tlv_child->has_value == 0) {
                LOGD("check_struct_node_all_has_value  tlv_child[%d]->tag:%x", index, tlv_child->tag);
                return TLV_FAIL;
            }
        }
    }

    return 0;
}

void set_struct_node_has_value(tlv_base *tlv)
{
    if (NULL != tlv) {
        tlv->has_value = 1;
    }
}

int32_t parse_and_skip_tlv_unknown_node(ta_parcel_t *parcel)
{
    //read tag
    uint16_t tag = 0;
    if (!parcel_read_uint16(parcel, &tag)) {
        return TLV_FAIL;
    }

    //read length
    uint16_t length = 0;
    if (!parcel_read_uint16(parcel, &length)) {
        return TLV_FAIL;
    }

    //pop data
    if (!parcel_pop_front(parcel, length)) {
        return TLV_FAIL;
    }

    return sizeof(tag) + sizeof(length) + length;
}

//���������������tlv struct������tlv struct�ĳ���(������tag��len)
int32_t parse_tlv_struct(tlv_base *tlv, ta_parcel_t *parcel)
{
    uint32_t child_total_length = 0;
    do {
        //��ȡ��һ��child_node��tag
        uint16_t tag = 0;
        if (!parcel_read_without_popdata(parcel, &tag, sizeof(tag))) {
            return TLV_FAIL;
        }

        //�����Ƿ��и�node
        tlv_base *tlv_child = get_empty_struct_node(tlv, tag);
        if (NULL == tlv_child) {
            //����һ��δ֪��tag, ����������
            int32_t unknown_child_length = parse_and_skip_tlv_unknown_node(parcel);
            if (unknown_child_length < 0) {
                //δ֪��child node ����ʧ��
                return TLV_FAIL;
            }
            //�����ɹ��������ܳ���
            child_total_length += unknown_child_length;
        } else {
            //�������child
            int32_t child_length = parse_tlv_node(tlv_child, parcel);
            if (child_length < 0) {
                //child����ʧ��
                return TLV_FAIL;
            }
            //�����ɹ�������Ϊ�ѽ����������ܳ���
            set_struct_node_has_value(tlv_child);
            child_total_length += child_length;
        }
    } while (child_total_length < tlv->length);

    if (child_total_length > tlv->length) {
        //������child�ܳ����Ѿ�������tlv struct��body len������ʧ��
        return TLV_FAIL;
    }

    //�ж��Ƿ���Ȼ��û�����Ŀ��ֶ�
    if (check_struct_node_all_has_value(tlv) != 0) {
        LOGE("parse_tlv_struct error, tag:%x", tlv->tag);
        return TLV_FAIL;
    }

    //�����ɹ�
    return child_total_length;
}

//��������������tlv struct������tlv struct�ĳ���(������tag��len)
int32_t encode_tlv_struct(tlv_base *tlv, ta_parcel_t *parcel)
{
    unsigned int index = 0;
    unsigned int member_count = *(unsigned int *)((char *)tlv + offsetof(tlv_offset_example, offset_count));
    unsigned int *offset = (unsigned int *)((char *)tlv + offsetof(tlv_offset_example, offset));

    uint32_t total_len = 0;
    for (index = 0; index < member_count; ++index) {
        tlv_base *tlv_child = (tlv_base *)(((char *)tlv) + offset[index]);
        int32_t child_len = encode_tlv_node(tlv_child, parcel);
        if (child_len < 0) {
            //child���ʧ��
            return TLV_FAIL;
        } else {
            total_len += child_len;
        }
    }

    return total_len;
}

//�������������ȡtlv struct�ĳ��ȣ�������tag��len
int32_t getlen_tlv_struct(tlv_base *tlv)
{
    unsigned int index = 0;
    unsigned int member_count = *(unsigned int *)((char *)tlv + offsetof(tlv_offset_example, offset_count));
    unsigned int *offset = (unsigned int *)((char *)tlv + offsetof(tlv_offset_example, offset));
    uint32_t child_total_length = 0;

    for (index = 0; index < member_count; ++index) {
        tlv_base *tlv_child = (tlv_base *)(((char *)tlv) + offset[index]);
        int32_t child_length = getlen_tlv_node(tlv_child);
        if (child_length <= 0 || child_total_length > (uint32_t)(MAX_INT_VALUE - child_length)) {
            return TLV_FAIL;
        } else {
            child_total_length += child_length;
        }
    }

    return (int32_t)child_total_length;
}

void deinit_tlv_struct(tlv_base *tlv)
{
    unsigned int index = 0;
    unsigned int member_count = *(unsigned int *)((char *)tlv + offsetof(tlv_offset_example, offset_count));
    unsigned int *offset = (unsigned int *)((char *)tlv + offsetof(tlv_offset_example, offset));

    for (index = 0; index < member_count; ++index) {
        tlv_base *tlv_child = (tlv_base *)(((char *)tlv) + offset[index]);
        deinit_tlv_node(tlv_child);
    }

    return;
}

TA_BOOL decode_tlv_message(tlv_base *msg, ta_parcel_t *parcel)
{
    // �����ж����
    if (NULL == msg || NULL == parcel) {
        return TA_FALSE;
    } else {
        //����msg��Ȼ���ж�msg body���صĳ����Ƿ���ȷ
        int32_t msg_len = parse_tlv_node(msg, parcel);
        if ((int32_t)(msg->length + sizeof(msg->length) + sizeof(msg->tag)) != msg_len) {
            return TA_FALSE;
        }

        //Ȼ���ж�parcel�Ƿ����꣬û�����꣬˵������������
        if (get_parcel_data_size(parcel) != 0) {
            return TA_FALSE;
        }
    }

    return TA_TRUE;
}


TA_BOOL encode_tlv_message(tlv_base *msg, ta_parcel_t *parcel)
{
    if (NULL == msg || NULL == parcel) {
        return TA_FALSE;
    } else {
        if (encode_tlv_node(msg, parcel) < 0) {
            return TA_FALSE;
        }
    }

    return TA_TRUE;
}

int32_t parse_tlv_buffer(tlv_base *tlv, ta_parcel_t *parcel)
{
    tlv_buffer *real_tlv = (tlv_buffer *)(tlv);

    if (parcel_read_parcel(parcel, &real_tlv->data, tlv->length, TA_FALSE)) {
        return tlv->length;
    } else {
        return TLV_FAIL;
    }
}

int32_t getlen_tlv_buffer(tlv_base *tlv)
{
    tlv_buffer *real_tlv = (tlv_buffer *)(tlv);
    return (int32_t)get_parcel_data_size(&real_tlv->data);
}

int32_t encode_tlv_buffer(tlv_base *tlv, ta_parcel_t *parcel)
{
    tlv_buffer *real_tlv = (tlv_buffer *)(tlv);
    int32_t len = getlen_tlv_buffer(tlv);
    if (len <= 0) {
        return len;
    }

    if (parcel_read_parcel(&real_tlv->data, parcel, len, TA_TRUE)) {
        return len;
    } else {
        return TLV_FAIL;
    }
}

void init_tlv_buffer(tlv_buffer *tlv, unsigned short check_tag)
{
    (void)memset_s(&tlv->base, sizeof(tlv->base), 0, sizeof(tlv->base));
    tlv->base.parse = parse_tlv_buffer;
    tlv->base.getlen = getlen_tlv_buffer;
    tlv->base.encode = encode_tlv_buffer;
    tlv->base.deinit = deinit_tlv_buffer;
    tlv->base.check_tag = check_tag;
    tlv->data = create_parcel(PARCEL_DEFAULT_LENGTH, PARCEL_DEFAULT_ALLOC_UNIT);
}

unsigned short get_tag(unsigned short check_tag, unsigned short default_tag)
{
    if (check_tag == USE_DEFAULT_TAG) {
        return default_tag;
    } else {
        return check_tag;
    }
}

void deinit_tlv_buffer(tlv_base *tlv)
{
    delete_parcel(&((tlv_buffer *)tlv)->data);
}




////////////////////////////////basic types
#ifdef IS_BIG_ENDIAN
DEFINE_TLV_FIX_LENGTH_TYPE(tlv_int64, NEED_REVERT)
DEFINE_TLV_FIX_LENGTH_TYPE(tlv_int32, NEED_REVERT)
DEFINE_TLV_FIX_LENGTH_TYPE(tlv_int16, NEED_REVERT)
DEFINE_TLV_FIX_LENGTH_TYPE(tlv_int8, NEED_REVERT)
DEFINE_TLV_FIX_LENGTH_TYPE(tlv_uint64, NEED_REVERT)
DEFINE_TLV_FIX_LENGTH_TYPE(tlv_uint32, NEED_REVERT)
DEFINE_TLV_FIX_LENGTH_TYPE(tlv_uint16, NEED_REVERT)
DEFINE_TLV_FIX_LENGTH_TYPE(tlv_uint8, NEED_REVERT)
#else
DEFINE_TLV_FIX_LENGTH_TYPE(tlv_int64, NO_REVERT)
DEFINE_TLV_FIX_LENGTH_TYPE(tlv_int32, NO_REVERT)
DEFINE_TLV_FIX_LENGTH_TYPE(tlv_int16, NO_REVERT)
DEFINE_TLV_FIX_LENGTH_TYPE(tlv_int8, NO_REVERT)
DEFINE_TLV_FIX_LENGTH_TYPE(tlv_uint64, NO_REVERT)
DEFINE_TLV_FIX_LENGTH_TYPE(tlv_uint32, NO_REVERT)
DEFINE_TLV_FIX_LENGTH_TYPE(tlv_uint16, NO_REVERT)
DEFINE_TLV_FIX_LENGTH_TYPE(tlv_uint8, NO_REVERT)
#endif
