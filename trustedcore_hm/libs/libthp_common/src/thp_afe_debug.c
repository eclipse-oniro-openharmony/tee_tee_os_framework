/*
* Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
* Description: common interface file
* Author: l00492120 & c00414356
* Create: 2017-01-20
* Notes: this file's api is for debug
*/
#include "thp_afe_debug.h"
#include "tee_fs.h"
#include "tee_mem_mgmt_api.h" /* TEE_Malloc */
#include "tee_log.h"
#include "tee_time_api.h"
#include "self_adapt_supplier.h"

// save frame data begin
// row clo  16*28  need get info form afe hal
#define LOG_RAWDATA_FILE  "thp_raw.txt"
#define LOG_TSALOG_FILE  "tsa_log.txt"
#ifdef THP_DEBUG_LOG
static int  raw_file = 0;
static int  tsa_logfile = 0;
#define RAW_BUFF_SIZE  1024
unsigned char* g_frame_buff = NULL;
unsigned char* g_tsa_buff = NULL;

void tsa_creat_log_file(void)
{
    if (raw_file == 0) {
        raw_file = fcreate(LOG_RAWDATA_FILE, 0x02);
        if (raw_file == 0)
            tlogd("afe get_rawfile fcreate is error\n");
    }

    if (tsa_logfile == 0) {
        tsa_logfile = fcreate(LOG_TSALOG_FILE, 0x02);
        if (tsa_logfile == 0)
            tlogd("afe tsa_logfile fcreate is error\n");
    }
    tlogd("logfitle create success!");
}

uint32_t thp_strlen(const char* str)
{
    if (str == NULL) {
        return 0;
    } else {
        const char* p = str;
        while (*p++ != '\0');
        return p - str - 1;
    }
}

int thp_itoa(long long  value, char* string, int radix)
{
    char tmp[65] = {'\0'}; // 65 is enough room for transfer
    char* tp = tmp;
    int i = 0;
    int sign;
    unsigned v = 0;
    char* sp = NULL;

    if (radix > 36 || radix <= 1) // only support 1 ~ 35 transfer
        return -1;

    sign = (radix == 10 && value < 0); // judge whether the number is decimal number

    if (sign)
        v = -value;
    else
        v = (unsigned)value;

    while (v || (tp == tmp)) {
        i = v % radix;
        v = v / radix;

        if (i < 10) // default is decimal, judge whether this is a number
            *tp++ = i + '0';
        else
            *tp++ = i + 'a' - 10; // judge whether hex value
    }

    if (string == NULL) // for char* point in
        return -1;

    sp = string;
    if (sign)
		*sp++ = '-';

    while (tp > tmp)
		*sp++ = *--tp;

    *sp++ = '\t';   // for raw data print format *****tab *****tab
    *sp = 0;
    return 0;
}


// use this function, Convert numbers to strings
void byteToHex(char* buf, uint16_t data)
{
    if (buf == NULL)
        return;
    const char* str = "0123456789ABCDEF";
    *buf++ = str[(data & 0xF000) >> 12];
    *buf++ = str[(data & 0x0F00) >> 8];
    *buf++ = str[(data & 0x00F0) >> 4];
    *buf++ = str[(data & 0x000F)];
    *buf++ = '\t';
}

unsigned long long thp_get_time(void)
{
    TEE_Time t;
    get_sys_rtc_time(&t);
    return (t.seconds << 10) + t.millis; // change seconds to millis
}

// time=[1491042582278]	frame_no=[10751]	scan_freq=[312]	status=[0x0001]	ctrlflag=[0020]	feature=[0060]
// time/ctrlflag/feature
int afe_save_rawdata(uint16_t* buffer)
{
    int ret = 0;
    static int rawDataNum = 0;
    uint8_t tmp[100] = {0}; // 100 is safe number for itoa
    char* head = NULL;
    static uint8_t frame_num = 0;
    tlogd("==>>afe_save_rawdata entry<<==\n");

    if (buffer == NULL)
        return FALSE;

    int buff_size = 60 * RAW_BUFF_SIZE; // set as log buff size
    if (g_frame_buff == NULL)
        g_frame_buff = (unsigned char*)TEE_Malloc(buff_size, 0);

    if (g_frame_buff == NULL) {
        tloge("g_frame_buff is NULL \n");
        return FALSE;
    }
    (void)memset_s(g_frame_buff, buff_size, 0, buff_size);

    frame_num++;

    head = "\n +++ start new frame +++\n";

    int ret = memcpy_s(g_frame_buff + rawDataNum, thp_strlen((const char*)head), head, thp_strlen((const char*)head));
    if(ret != EOK)
        return FALSE;
    rawDataNum += thp_strlen((const char*)head);

    for (int i = 0; i < g_row_num * g_column_num; i++) {
        uint16_t data = *(buffer + i);
        thp_itoa(data, (char *)tmp, 10); // decimal
        ret = memcpy_s(g_frame_buff + rawDataNum, thp_strlen((const char*)tmp), tmp, thp_strlen((const char*)tmp));
        if(ret != EOK)
            return FALSE;
        rawDataNum += thp_strlen((const char*)tmp);

        if ((i + 1) % g_column_num == 0) {
            ret = memcpy_s(g_frame_buff + rawDataNum, thp_strlen((const char*)"\n"),
                           "\n", thp_strlen((const char*)"\n"));
            if(ret != EOK)
                return FALSE;
            rawDataNum += thp_strlen((const char*)"\n");
        }
    }

    if (frame_num < 10) { // continue storeage 10 frame
        tlogd("<<==afe_save_rawdata exit==>> rawDataNum = %d, frame_num = %d\n", rawDataNum, frame_num);
        return 0;
    }

    raw_file = fopen(LOG_RAWDATA_FILE, 0x02);
    if (raw_file == 0) {
        tlogd("afe get_rawfile fopen is error\n");
        return FALSE;
    }

    fseek(raw_file, 0, SEEK_END);
    fwrite(g_frame_buff, rawDataNum, raw_file);
    ret = fclose(raw_file);
    raw_file = 0;
    SLogTrace("<<==afe_save_rawdata exit==>> rawDataNum = %d, frame_num = %d\n", rawDataNum, frame_num);
    rawDataNum = 0;
    frame_num = 0;
    return ret;
}
// save frame data end
// row clo  16*28  need get info form afe hal


// save log begin  /sec_storage/tsa_log.txt
// register call bcak fun for tsa lib
static const int CHARACTER_LEN = 1;
void log_append_tsa(char const c)
{
    int rawDataNum = 0;
    int8_t tmp = c;
    static uint16_t logdata_count = 0;

    if (g_tsa_buff == NULL)
        g_tsa_buff = (unsigned char*)TEE_Malloc(RAW_BUFF_SIZE, 0); // 1024 is a safe number for tsa log

    if (g_tsa_buff == NULL) {
        tloge("g_frame_buff is NULL \n");
        return;
    }
    (void)memset_s((void *)g_tsa_buff, RAW_BUFF_SIZE, 0, RAW_BUFF_SIZE);

    logdata_count++;
    int ret = memcpy_s(g_tsa_buff + logdata_count, CHARACTER_LEN, &tmp, CHARACTER_LEN);
    if(ret != EOK)
        return;

    if (logdata_count < 1000) // continue storage 1000 character
        return;

    tsa_logfile = fopen(LOG_TSALOG_FILE, 0x02);
    if (tsa_logfile == 0) {
        tloge("afe get_rawfile fopen is error\n");
        return;
    }

    fseek(tsa_logfile, 0, SEEK_END);
    rawDataNum += fwrite(g_tsa_buff, logdata_count, tsa_logfile);
    tlogd("afe save tsa_logfile = %d\n", rawDataNum);
    fclose(tsa_logfile);
    tsa_logfile = 0;
    logdata_count = 0;
}

void debug_free_memory(void)
{
    if (g_tsa_buff != NULL)
        TEE_Free(g_tsa_buff);

    if (g_frame_buff != NULL)
        TEE_Free(g_frame_buff);

    g_frame_buff = NULL;
    g_tsa_buff = NULL;
}
// save log end  /sec_storage/tsa_log.txt
// register call bcak fun for tsa lib
#endif

void show_mem_usage(const char* func)
{
    (void)func;
}

