#ifndef TA_BASIC_LIBS_H
#define TA_BASIC_LIBS_H

#include "tee_internal_api.h"
#include "TA_Parcel.h"
//#define AUTH_FAKE_TEST
uint32_t TA_Strlen(const char *str);
uint64_t get_time();
void itoa(int val, char *buf, unsigned radix);
//void printHexWithTag(const char *tag, const unsigned char *IN, int size);

#endif
