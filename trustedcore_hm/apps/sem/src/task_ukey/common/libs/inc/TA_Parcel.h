#ifndef TA_PARCEL_H
#define TA_PARCEL_H

#include "TA_Types.h"

#define PARCEL_DEFAULT_LENGTH 0
#define PARCEL_DEFAULT_ALLOC_UNIT 0

typedef struct {
	char *data;
	unsigned int begin_pos;
	unsigned int end_pos;
	unsigned int length;
	unsigned int alloc_unit;
} ta_parcel_t;

void TA_Security_Memcopy(void *dst, void *src, uint32_t size);
ta_parcel_t create_parcel(uint32_t size, uint32_t alloc_unit);
void delete_parcel(ta_parcel_t *parcel);

TA_BOOL parcel_read_without_popdata(ta_parcel_t *parcel, void *dst, uint32_t data_size);

TA_BOOL parcel_read(ta_parcel_t *parcel, void *dst, uint32_t data_size);
TA_BOOL parcel_write(ta_parcel_t *parcel, const void *src, uint32_t data_size);
TA_BOOL parcel_read_revert(ta_parcel_t *parcel, void *dst, uint32_t data_size);
TA_BOOL parcel_write_revert(ta_parcel_t *parcel, void *src, uint32_t data_size);
uint32_t get_parcel_data_size(const ta_parcel_t *parcel);
const char *get_parcel_data(const ta_parcel_t *parcel);


TA_BOOL parcel_read_int32(ta_parcel_t *parcel, int *dst);
TA_BOOL parcel_read_uint32(ta_parcel_t *parcel, uint32_t *dst);
TA_BOOL parcel_read_int16(ta_parcel_t *parcel, short *dst);
TA_BOOL parcel_read_uint16(ta_parcel_t *parcel, uint16_t *dst);
TA_BOOL parcel_read_int8(ta_parcel_t *parcel, char *dst);
TA_BOOL parcel_read_uint8(ta_parcel_t *parcel, uint8_t *dst);
TA_BOOL parcel_read_uint64(ta_parcel_t *parcel, uint64_t *dst);
TA_BOOL parcel_read_int64(ta_parcel_t *parcel, int64_t *dst);
TA_BOOL parcel_write_int32(ta_parcel_t *parcel, int src);
TA_BOOL parcel_write_uint32(ta_parcel_t *parcel, uint32_t src);
TA_BOOL parcel_write_int16(ta_parcel_t *parcel, short src);
TA_BOOL parcel_write_uint16(ta_parcel_t *parcel, uint16_t src);
TA_BOOL parcel_write_int8(ta_parcel_t *parcel, char src);
TA_BOOL parcel_write_uint8(ta_parcel_t *parcel, uint8_t src);
TA_BOOL parcel_write_uint64(ta_parcel_t *parcel, uint64_t src);
TA_BOOL parcel_write_int64(ta_parcel_t *parcel, int64_t src);
TA_BOOL parcel_write_string(ta_parcel_t *parcel, char *str);
TA_BOOL parcel_read_string(ta_parcel_t *parcel, char **str);
TA_BOOL parcel_read_parcel(ta_parcel_t *src, ta_parcel_t *dst, uint32_t size, TA_BOOL copy);
TA_BOOL parcel_copy(ta_parcel_t *src, ta_parcel_t *dst);


TA_BOOL parcel_read_int32_revert(ta_parcel_t *parcel, int32_t *dst);
TA_BOOL parcel_read_uint32_revert(ta_parcel_t *parcel, uint32_t *dst);
TA_BOOL parcel_read_int16_revert(ta_parcel_t *parcel, short *dst);
TA_BOOL parcel_read_uint16_revert(ta_parcel_t *parcel, uint16_t *dst);
TA_BOOL parcel_read_int8_revert(ta_parcel_t *parcel, char *dst);
TA_BOOL parcel_read_uint8_revert(ta_parcel_t *parcel, uint8_t *dst);
TA_BOOL parcel_read_uint64_revert(ta_parcel_t *parcel, uint64_t *dst);
TA_BOOL parcel_read_int64_revert(ta_parcel_t *parcel, int64_t *dst);

TA_BOOL parcel_write_int32_revert(ta_parcel_t *parcel, int src);
TA_BOOL parcel_write_uint32_revert(ta_parcel_t *parcel, uint32_t src);
TA_BOOL parcel_write_int16_revert(ta_parcel_t *parcel, short src);
TA_BOOL parcel_write_uint16_revert(ta_parcel_t *parcel, uint16_t src);
TA_BOOL parcel_write_int8_revert(ta_parcel_t *parcel, char src);
TA_BOOL parcel_write_uint8_revert(ta_parcel_t *parcel, uint8_t src);
TA_BOOL parcel_write_uint64_revert(ta_parcel_t *parcel, uint64_t src);
TA_BOOL parcel_write_int64_revert(ta_parcel_t *parcel, int64_t src);

void data_revert(void *data, uint32_t length);
TA_BOOL parcel_pop_back(ta_parcel_t *parcel, uint32_t size);
TA_BOOL parcel_pop_front(ta_parcel_t *parcel, uint32_t size);

TA_BOOL parcel_erase_block(ta_parcel_t *parcel, uint32_t start, uint32_t data_size,void *dst);
#endif