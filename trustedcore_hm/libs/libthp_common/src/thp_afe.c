/*
* Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
* Description: common interface file
* Author: l00492120 & c00414356
* Create: 2017-01-20
* Notes: this file's api is for init and get points
*/
#include "TSA_Lib.h"
#include "thp_afe.h"
#include "self_adapt_supplier.h"
#include "thp_afe_debug.h"
#include "tee_log.h"
#include "tee_mem_mgmt_api.h"
#include "thp_afe_driver.h"
#include "thp_afe_wrapper.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TS_GET_FRAME        0x1
#define TS_SPI_SYNC         0x2
#define TS_IRQ_CTL          0x3
#define TS_GET_PRO_ID       0x4
#define TS_SYNC_FRAME       0x5

#define TYPE_TOUCH          64
#define TYPE_RELEASE        32

#define INPUT_MT_WRAPPER_MAX_FINGERS  10

uint32_t g_ctrlflag = 0;
#define TSA_VOLATILE_CTRLFLAGS \
        (TSA_CTRL_POWER_ON | \
        TSA_CTRL_RESET | \
        TSA_CTRL_WAKE_UP | \
        TSA_CTRL_RE_CALIBRATION | \
        TSA_CTRL_FREQ_HOPPED)

#define tsa_set_boot_flag(void)         set_bit(g_ctrlflag, TSA_CTRL_POWER_ON)
#define tsa_set_reset_flag(void)        set_bit(g_ctrlflag, TSA_CTRL_RESET)
#define tsa_clear_ctrlflag(void)        unset_bit(g_ctrlflag, TSA_VOLATILE_CTRLFLAGS)

static void tsa_prop_version_info(void);
static void afe_prop_version(void);
static void tsa_prop_version(void);

int g_row_num = 0;
int g_column_num = 0;

static int tsa_get_project_id(void)
{
    int ret;
    char project_id[THP_PROJECT_ID_LEN + 1];

    ret = thp_tee_getProjectId((char*)project_id);
    if(strlen(project_id) == (THP_PROJECT_ID_LEN - 1))
        project_id[THP_PROJECT_ID_LEN - 1] = '0'; // if the length is 9, set 0 to tenth
    project_id[THP_PROJECT_ID_LEN] = '\0';
    ret = thp_afe_wrapper_init(project_id);

    return ret;
}

static void tsa_prop_version_info(void)
{
    tsa_prop_version();
    afe_prop_version();
}

static void tsa_init_algo(void)
{
    TSA_Init_UI();
    TSA_InitProject_UI(g_tsa_projectid);
    tsa_set_reset_flag();
    tsa_set_boot_flag();
}

static void tsa_prop_version(void)
{
    int version_num = TSA_GetVersion();
    (void)version_num;
    tlogi("version num is %d", version_num);
}

const uint8_t TOUCH_REPORTING = 1;
const uint8_t NO_TOUCH = 0;
static void tsa_obtain_main(ts_tui_finger* data)
{
    uint8_t index;
    uint8_t t_num;
    uint8_t index_max = 0;
    static uint8_t report_flag = 0;

    if (data == NULL) {
        tloge("in tsa_obtain_main data is null");
        return;
    }

    (void)memset_s(data, sizeof(ts_tui_finger), 0, sizeof(ts_tui_finger));

    t_num = TSA_RptTouchNum();
    if (t_num > INPUT_MT_WRAPPER_MAX_FINGERS) {
        tloge("detect touch down number as: %d, bigger than: %d\n", TSA_RptTouchNum(), INPUT_MT_WRAPPER_MAX_FINGERS);
        return;
    }

    for (index = 0; index < t_num; index++) {
        if (t_num == 0) {
            index_max = 0;
            break;
        } else if (TSA_RptTouchXPos(index) == 0 || TSA_RptTouchYPos(index_max) == 0) {
            continue;
        } else {
            if (TSA_RptTouchPressure(index_max) < TSA_RptTouchPressure(index))
                index_max = index;
        }
    }

    if (report_flag == TOUCH_REPORTING) // 1 indicate touch is reporting
        data->status = (t_num == 0) ? TYPE_RELEASE : TYPE_TOUCH;
    else
        data->status = (t_num == 0) ? 0x00 : TYPE_TOUCH;

    data->x = TSA_RptTouchXPos(index_max);
    data->y = TSA_RptTouchYPos(index_max);
    data->pressure = TSA_RptTouchPressure(index_max);
    data->major = TSA_RptTouchAxisMajor(index_max);
    data->minor = TSA_RptTouchAxisMinor(index_max);
    data->orientation = TSA_RptTouchAxisAngle(index_max);
    report_flag = (t_num == 0) ? NO_TOUCH : TOUCH_REPORTING;
}

static void thp_handle_frame_data(const THP_AFE_FRAME_DATA_STRUCT* frame, ts_tui_finger* data)
{
    TSA_Processing(frame->grid_data, g_ctrlflag, timeval_to_ms(frame->time_stamp));
    tsa_clear_ctrlflag();
    tsa_obtain_main(data);
}

static void afe_prop_version(void)
{
    const THP_AFE_HW_CAP_STRUCT* m_hw_cap = g_afe_api_wrapper->thp_afe_get_hw_cap();
    if (m_hw_cap == NULL) {
        tloge("thp_afe_get_hw_cap failed");
        return;
    }
    g_column_num = m_hw_cap->num_col;
    g_row_num = m_hw_cap->num_row;
}

int tui_ta_get_tpdata_thp(ts_tui_finger* data)
{
    const THP_AFE_FRAME_DATA_STRUCT* frame = NULL;
    tlogd("==>>tui_ta_get_tpdata_thp\n");

    if (g_afe_api_wrapper == NULL || data == NULL) {
        tloge("g_afe_api_wrapper or data is NULL");
        return TRADITION;
    }

    frame = g_afe_api_wrapper->thp_afe_get_frame();
    if (frame == NULL) {
        (void)__ts_ioctl(TS_SYNC_FRAME, NULL);
        tloge("skipbelow due to thp_afe_get_frame is null\n");
        return -1;
    }

    if (frame->grid_data == NULL) {
        tloge("skipbelow due to griddata null\n");
        return -1;
    }

#ifdef THP_DEBUG_LOG
    afe_save_rawdata(frame->grid_data);
#endif

    thp_handle_frame_data(frame, data);
    tlogd("x:%d, y:%d, pressure:%d,status:%d\n", data->x, data->y, data->pressure, data->status);
    (void)__ts_ioctl(TS_SYNC_FRAME, NULL);
    return 0;
}

int thp_ta_init(void)
{
    THP_AFE_ERR_ENUM error;
    tlogd(" ==> thp_ta_init entry\n");

    error = thp_tee_Init();
    if (error != THP_AFE_OK) {
        tloge("tsa_init_info error return: %d \n", error);
        return error;
    }
    error =  tsa_get_project_id();
    if (error != THP_AFE_OK) {
        tloge("tsa_get_project_id error return: %d \n", error);
        if (error > 0)
            error = THP_AFE_OK;// maye it's tradition solution
        goto deinit;
    }

    error = g_afe_api_wrapper->thp_afe_open_project(g_tsa_projectid);
    if (error != THP_AFE_OK) {
        tloge("thp_afe_open error return: %d \n", error);
        goto deinit;
    }
    error = g_afe_api_wrapper->thp_afe_start();
    if (error != THP_AFE_OK) {
        tloge("thp_afe_start error return: %d \n", error);
        goto thp_close;
    }
    tlogd("the thp_afe_start return %d!", error);

#ifdef THP_DEBUG_LOG
    tsa_creat_log_file();
#endif

    tsa_init_algo();
    tsa_prop_version_info();
    thp_tee_setIrq(1);
    show_mem_usage((char*)__func__);
    tloge("thp_ta_init success.\n");
    goto out;

thp_close:
    g_afe_api_wrapper->thp_afe_close();
deinit:
    thp_tee_deInit();
out:
    return error;
}

int  thp_ta_deinit(void)
{
    THP_AFE_ERR_ENUM error;

    tlogd("==>thp_ta_deinit entry \n");
    if (g_afe_api_wrapper == NULL) {
        tloge("g_afe_api_wrapper is null");
        return 0;
    }

    thp_tee_setIrq(0);
    error = g_afe_api_wrapper->thp_afe_stop();
    if (error != THP_AFE_OK) {
        tloge("thp_afe_stop error return: %d \n", error);
        goto out;
    }

    error = g_afe_api_wrapper->thp_afe_close();
    if (error != THP_AFE_OK) {
        tloge("thp_afe_close error return: %d \n", error);
        goto out;
    }

out:
    thp_tee_deInit();
#ifdef THP_DEBUG_LOG
    debug_free_memory();
#endif
    show_mem_usage((char*)__func__);
    return error;
}

int thp_init()
{
    return thp_ta_init();
}

int thp_deinit()
{
    return thp_ta_deinit();
}

int tui_get_tpdata_thp(ts_tui_finger* data)
{
    return tui_ta_get_tpdata_thp(data);
}

#ifdef __cplusplus
}
#endif
