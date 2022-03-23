#include "TA_Parcel.h"
#include "TA_Log.h"
#include "libhwsecurec/securec.h"

#define PARCEL_DEFAULT_INCREASE_STEP 512
#define UINT_MAX     0xffffffffU

void TA_Security_Memcopy(void *dst, void *src, uint32_t size)
{
    char *c_dst = (char *) dst;
    char *c_src = (char *) src;

    if (NULL == c_dst || NULL == c_src || size == 0) {
        return;
    }

    if (dst > src) {
        int index = size - 1;
        for (; index >= 0; --index) {
            c_dst[index] = c_src[index];
        }
    } else {
        int index = 0;
        for (; index < (int) size; ++index) {
            c_dst[index] = c_src[index];
        }
    }
}

ta_parcel_t create_parcel(uint32_t size, uint32_t alloc_unit)
{
    ta_parcel_t parcel;
    (void)memset_s(&parcel, sizeof(parcel), 0, sizeof(parcel));
    parcel.alloc_unit = alloc_unit;
    if (parcel.alloc_unit == 0) {
        parcel.alloc_unit = PARCEL_DEFAULT_INCREASE_STEP;
    }

    if (size > 0) {
        parcel.data = TEE_Malloc(size, 0);
        if (parcel.data != NULL) {
            parcel.length = size;
        }
    }

    return parcel;
}

void delete_parcel(ta_parcel_t *parcel)
{
    if (parcel != NULL) {
        if (parcel->data != NULL) {
            TEE_Free(parcel->data);
            parcel->data = 0;
        }

        parcel->length = 0;
        parcel->begin_pos = 0;
        parcel->end_pos = 0;
    }
}

uint32_t get_parcel_data_size(const ta_parcel_t *parcel)
{
    if (parcel == NULL) {
        return 0;
    }

    if (parcel->end_pos >= parcel->begin_pos) {
        return parcel->end_pos - parcel->begin_pos;
    }

    return 0;
}

const char *get_parcel_data(const ta_parcel_t *parcel)
{
    if (parcel == NULL) {
        return NULL;
    }

    return parcel->data + parcel->begin_pos;
}

TA_BOOL parcel_read_without_popdata(ta_parcel_t *parcel, void *dst, uint32_t data_size)
{
#ifdef IS_BIG_ENDIAN
    TA_BOOL ret = parcel_read_revert(parcel, dst, data_size);
#else
    TA_BOOL ret = parcel_read(parcel, dst, data_size);
#endif
    if (ret == TA_TRUE) {
        parcel->begin_pos -= data_size;
    }
    return ret;
}

TA_BOOL parcel_read(ta_parcel_t *parcel, void *dst, uint32_t data_size)
{
    errno_t rc = EOK;

    if (parcel == NULL || dst == NULL || data_size == 0) {
        LOGE("Bad Parameters!");
        return TA_FALSE;
    }

    if (parcel->begin_pos > UINT_MAX - data_size) {
        LOGE("Bad Parameters!");
        return TA_FALSE;
    }

    if (parcel->begin_pos + data_size > parcel->end_pos) {
        LOGE("parcel size < data_size you want to read: parcel size %d while data_size %d!", get_parcel_data_size(parcel), data_size);
        return TA_FALSE;
    }

    rc = memmove_s(dst,
               data_size,
               parcel->data + parcel->begin_pos,
               data_size);
    if (rc != EOK) {
        LOGE("get data failed:%d.\n", rc);
        return TA_FALSE;
    }

    parcel->begin_pos += data_size;
    return TA_TRUE;
}

TA_BOOL parcel_erase_block(ta_parcel_t *parcel, uint32_t start, uint32_t data_size,void *dst)
{
    errno_t rc = EOK;

    if (parcel == NULL || dst == NULL || data_size == 0) {
        LOGE("Bad Parameters!");
        return TA_FALSE;
    }

    if(start > UINT_MAX - data_size) {
        return TA_FALSE;
    }

    uint32_t parcel_size_org = get_parcel_data_size(parcel) ;

    if(parcel_size_org < start+data_size) {
        return TA_FALSE;
    }

    char* begin_cpy = parcel->data+parcel->begin_pos+start;
    uint32_t copy_size = parcel_size_org - start - data_size;

    rc = memmove_s(dst, data_size, begin_cpy, data_size);
    if (rc != EOK) {
        LOGE("get data failed:%d.\n", rc);
        return TA_FALSE;
    }
    if(0 != copy_size)
    {
        rc = memmove_s(begin_cpy,
                          copy_size,
                          begin_cpy + data_size,
                          copy_size);
        if (rc != EOK) {
            LOGE("cover data failed:%d.\n", rc);
            return TA_FALSE;
        }
    }
    parcel->end_pos -= data_size;
    return TA_TRUE;
}


TA_BOOL parcel_read_revert(ta_parcel_t *parcel, void *dst, uint32_t data_size)
{
    if (parcel_read(parcel, dst, data_size)) {
        data_revert(dst, data_size);
        return TA_TRUE;
    } else {
        return TA_FALSE;
    }
}


TA_BOOL parcel_write_revert(ta_parcel_t *parcel, void *src, uint32_t data_size)
{
    TA_BOOL ret = TA_FALSE;
    errno_t rc = EOK;
    void *src_cpy = TEE_Malloc(data_size, 0);

    if (src_cpy == NULL) {
        return TA_FALSE;
    }

    rc = memmove_s(src_cpy, data_size, src, data_size);
    if (rc != EOK) {
        TEE_Free(src_cpy);
        return TA_FALSE;
    }

    data_revert(src_cpy, data_size);

    ret = parcel_write(parcel, src_cpy,  data_size);
    TEE_Free(src_cpy);
    return ret;
}

TA_BOOL parcel_read_int32(ta_parcel_t *parcel, int *dst)
{
    return parcel_read(parcel, dst, sizeof(int));
}

TA_BOOL parcel_read_uint32(ta_parcel_t *parcel, uint32_t *dst)
{
    return parcel_read(parcel, dst, sizeof(uint32_t));
}

TA_BOOL parcel_read_int16(ta_parcel_t *parcel, short *dst)
{
    return parcel_read(parcel, dst, sizeof(short));
}

TA_BOOL parcel_read_uint16(ta_parcel_t *parcel, uint16_t *dst)
{
    return parcel_read(parcel, dst, sizeof(uint16_t));
}

TA_BOOL parcel_read_int8(ta_parcel_t *parcel, char *dst)
{
    return parcel_read(parcel, dst, sizeof(char));
}

TA_BOOL parcel_read_uint8(ta_parcel_t *parcel, uint8_t *dst)
{
    return parcel_read(parcel, dst, sizeof(uint8_t));
}

TA_BOOL parcel_read_uint64(ta_parcel_t *parcel, uint64_t *dst)
{
    return parcel_read(parcel, dst, sizeof(uint64_t));
}

TA_BOOL parcel_read_int64(ta_parcel_t *parcel, int64_t *dst)
{
    return parcel_read(parcel, dst, sizeof(int64_t));
}

static TA_BOOL parcel_increase(ta_parcel_t *parcel, uint32_t size)
{
    if (size > 10 * 1024) {
        LOGE("parcel_increase failed0:%d", size);
    }
    if (parcel == NULL || size == 0) {
        LOGE("parcel_increase failed1");
        return TA_FALSE;
    }
    if (parcel->data == NULL) {
        if (parcel->length != 0) {
            LOGE("parcel_increase failed2");
            return TA_FALSE;
        }
        (*parcel) = create_parcel(size, parcel->alloc_unit);
        if (parcel->data == NULL) {
            LOGE("parcel_increase failed3");
            return TA_FALSE;
        } else {
            return TA_TRUE;
        }
    } else {
        if (parcel->length >= size) {
            LOGE("parcel_increase failed4");
            return TA_FALSE;
        } else {
            char *new_data = TEE_Realloc(parcel->data, size);
            if (new_data == NULL) {
                LOGE("parcel_increase failed5");
                return TA_FALSE;
            } else {
                parcel->data = new_data;
                parcel->length = size;
                return TA_TRUE;
            }
        }
    }
}

static void parcel_recycle(ta_parcel_t *parcel)
{
    if (parcel) {
        if (parcel->data && parcel->begin_pos >= parcel->alloc_unit) {
            uint32_t content_size = parcel->end_pos - parcel->begin_pos;
            if (content_size > 0) {
                TA_Security_Memcopy(parcel->data, parcel->data + parcel->begin_pos, parcel->end_pos - parcel->begin_pos);
            }

            parcel->begin_pos = 0;
            parcel->end_pos = content_size;
        }
    }
}

static uint32_t get_parcel_increase_size(ta_parcel_t *parcel, uint32_t new_size)
{
    if (parcel == NULL) {
        return 0;
    } else {
        if (new_size % parcel->alloc_unit) {
            return (new_size / parcel->alloc_unit + 1) * parcel->alloc_unit;
        } else {
            return (new_size / parcel->alloc_unit) * parcel->alloc_unit;
        }
    }
}

TA_BOOL parcel_write(ta_parcel_t *parcel, const void *src, uint32_t data_size)
{
    errno_t rc = EOK;
    if (parcel == NULL || src == NULL || data_size == 0) {
        LOGE("Bad Parameters!");
        return TA_FALSE;
    }

    if (parcel->end_pos > UINT_MAX - data_size)
    {
        LOGE("Bad Parameters overflow!");
        return TA_FALSE;
    }

    if (parcel->end_pos + data_size > parcel->length) {
        parcel_recycle(parcel);
        if (parcel->end_pos + data_size > parcel->length) {
            uint32_t new_size = get_parcel_increase_size(parcel, parcel->end_pos + data_size);
            if (!parcel_increase(parcel, new_size)) {
                LOGE("parcel_increase failed");
                return TA_FALSE;
            }
        }
    }
    rc = memmove_s(parcel->data + parcel->end_pos, data_size, src, data_size);
    if (rc != EOK) {
        LOGE("get data failed:%d.\n", rc);
        return TA_FALSE;
    }
    parcel->end_pos += data_size;
    return TA_TRUE;
}

TA_BOOL parcel_write_int32(ta_parcel_t *parcel, int src)
{
    return parcel_write(parcel, &src, sizeof(src));
}

TA_BOOL parcel_write_uint32(ta_parcel_t *parcel, uint32_t src)
{
    return parcel_write(parcel, &src, sizeof(src));
}

TA_BOOL parcel_write_int16(ta_parcel_t *parcel, short src)
{
    return parcel_write(parcel, &src, sizeof(src));
}

TA_BOOL parcel_write_uint16(ta_parcel_t *parcel, uint16_t src)
{
    return parcel_write(parcel, &src, sizeof(src));
}

TA_BOOL parcel_write_int8(ta_parcel_t *parcel, char src)
{
    return parcel_write(parcel, &src, sizeof(src));
}

TA_BOOL parcel_write_uint8(ta_parcel_t *parcel, uint8_t src)
{
    return parcel_write(parcel, &src, sizeof(src));
}

TA_BOOL parcel_write_uint64(ta_parcel_t *parcel, uint64_t src)
{
    return parcel_write(parcel, &src, sizeof(src));
}

TA_BOOL parcel_write_int64(ta_parcel_t *parcel, int64_t src)
{
    return parcel_write(parcel, &src, sizeof(src));
}

TA_BOOL parcel_write_string(ta_parcel_t *parcel, char *str)
{
    if (NULL == parcel || str == NULL) {
        return TA_FALSE;
    } else {
        uint32_t length = strlen(str);
        if (!parcel_write_int32(parcel, length)) {
            return TA_FALSE;
        }

        if (length > 0) {
            return parcel_write(parcel, str, length);
        } else {
            return TA_TRUE;
        }
    }
}

TA_BOOL parcel_read_string(ta_parcel_t *parcel, char **str)
{
    if (NULL == parcel || str == NULL) {
        return TA_FALSE;
    } else {
        int str_len = 0;
        if (!parcel_read_int32(parcel, &str_len)) {
            return TA_FALSE;
        }

        (*str) = TEE_Malloc(str_len, 0);
        if (*str == NULL) {
            return TA_FALSE;
        }

        return parcel_read(parcel, *str, str_len);
    }
}

TA_BOOL parcel_read_parcel(ta_parcel_t *src, ta_parcel_t *dst, uint32_t size, TA_BOOL copy)
{
    if (NULL == src || NULL == dst) {
        return TA_FALSE;
    } else {
        if (get_parcel_data_size(src) < size) {
            return TA_FALSE;
        } else {
            if (!parcel_write(dst, (void*)get_parcel_data(src), size))
            {
                return TA_FALSE;
            }

            if (!copy) {
                src->begin_pos += size;
            }
            return TA_TRUE;
        }
    }
}

TA_BOOL parcel_copy(ta_parcel_t *src, ta_parcel_t *dst)
{
    if (NULL == src || NULL == dst) {
        return TA_FALSE;
    }

    if (get_parcel_data_size(src) == 0) {
        return TA_TRUE;
    }

    return parcel_read_parcel(src, dst, get_parcel_data_size(src), TA_TRUE);
}

void data_revert(void *data, uint32_t length)
{
    if (NULL != data) {
        char *pc = (char *) data;
        uint32_t i = 0;
        for (; i < length / 2; ++i) {
            //swap p[i] and p[length-i-1]
            pc[i] ^= pc[length - i - 1];
            pc[length - i - 1] ^= pc[i];
            pc[i] ^= pc[length - i - 1];
        }
    }
}

TA_BOOL parcel_read_int32_revert(ta_parcel_t *parcel, int32_t *dst)
{
    TA_BOOL ret = parcel_read(parcel, dst, sizeof(int));
    if (ret) {
        data_revert(dst, sizeof(int));
    }

    return ret;
}

TA_BOOL parcel_read_uint32_revert(ta_parcel_t *parcel, uint32_t *dst)
{
    TA_BOOL ret = parcel_read(parcel, dst, sizeof(uint32_t));
    if (ret) {
        data_revert(dst, sizeof(uint32_t));
    }

    return ret;
}

TA_BOOL parcel_read_int16_revert(ta_parcel_t *parcel, short *dst)
{
    TA_BOOL ret = parcel_read(parcel, dst, sizeof(short));
    if (ret) {
        data_revert(dst, sizeof(short));
    }

    return ret;
}

TA_BOOL parcel_read_uint16_revert(ta_parcel_t *parcel, uint16_t *dst)
{
    if(NULL == parcel || NULL == dst)
    {
        return TA_FALSE;
    }

    TA_BOOL ret = parcel_read(parcel, dst, sizeof(uint16_t));
    if (ret) {
        data_revert(dst, sizeof(uint16_t));
    }

    return ret;
}

TA_BOOL parcel_read_int8_revert(ta_parcel_t *parcel, char *dst)
{
    return parcel_read(parcel, dst, sizeof(char));
}

TA_BOOL parcel_read_uint8_revert(ta_parcel_t *parcel, uint8_t *dst)
{
    return parcel_read(parcel, dst, sizeof(uint8_t));
}

TA_BOOL parcel_read_uint64_revert(ta_parcel_t *parcel, uint64_t *dst)
{
    TA_BOOL ret = parcel_read(parcel, dst, sizeof(uint64_t));
    if (ret) {
        data_revert(dst, sizeof(uint64_t));
    }

    return ret;
}

TA_BOOL parcel_read_int64_revert(ta_parcel_t *parcel, int64_t *dst)
{
    TA_BOOL ret = parcel_read(parcel, dst, sizeof(int64_t));
    if (ret) {
        data_revert(dst, sizeof(int64_t));
    }

    return ret;
}

TA_BOOL parcel_write_int32_revert(ta_parcel_t *parcel, int src)
{
    data_revert(&src, sizeof(src));
    return parcel_write_int32(parcel, src);
}

TA_BOOL parcel_write_uint32_revert(ta_parcel_t *parcel, uint32_t src)
{
    data_revert(&src, sizeof(src));
    return parcel_write_uint32(parcel, src);
}

TA_BOOL parcel_write_int16_revert(ta_parcel_t *parcel, short src)
{
    data_revert(&src, sizeof(src));
    return parcel_write_int16(parcel, src);
}

TA_BOOL parcel_write_uint16_revert(ta_parcel_t *parcel, uint16_t src)
{
    data_revert(&src, sizeof(src));
    return parcel_write_uint16(parcel, src);
}

TA_BOOL parcel_write_int8_revert(ta_parcel_t *parcel, char src)
{
    return parcel_write_int8(parcel, src);
}

TA_BOOL parcel_write_uint8_revert(ta_parcel_t *parcel, uint8_t src)
{
    return parcel_write_uint8(parcel, src);
}

TA_BOOL parcel_write_uint64_revert(ta_parcel_t *parcel, uint64_t src)
{
    data_revert(&src, sizeof(src));
    return parcel_write_uint64(parcel, src);
}

TA_BOOL parcel_write_int64_revert(ta_parcel_t *parcel, int64_t src)
{
    data_revert(&src, sizeof(src));
    return parcel_write_int64(parcel, src);
}

TA_BOOL parcel_pop_back(ta_parcel_t *parcel, uint32_t size)
{
    if (NULL != parcel && size > 0 && get_parcel_data_size(parcel) >= size) {
        parcel->end_pos -= size;
        return TA_TRUE;
    }
    return TA_FALSE;
}

TA_BOOL parcel_pop_front(ta_parcel_t *parcel, uint32_t size)
{
    if (NULL != parcel && size > 0 && get_parcel_data_size(parcel) >= size) {
        parcel->begin_pos += size;
        return TA_TRUE;
    }
    return TA_FALSE;
}
