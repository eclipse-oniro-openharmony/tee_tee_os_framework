/*
* Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
* Description: common interface file
* Author: c00365671
* Create: 2017-01-20
* Notes: this file's api is tsa algo interface
*/

#ifndef __THP_AFE_HAL_H_
#define __THP_AFE_HAL_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TRADITION 0X1234
/* defines THP AFE HAL spec major version */
#define THP_AFE_HAL_SPEC_MAJOR_VERSION         0
/* defines THP AFE HAL spec minor version */
#define THP_AFE_HAL_SPEC_MINOR_VERSION         1
/* defines THP AFE HAL spec patch version */
#define THP_AFE_HAL_SPEC_PATCH_VERSION         17
/* defines THP AFE HAL spec version */
#define THP_AFE_HAL_SPEC_VERSION \
    (THP_AFE_HAL_SPEC_MAJOR_VERSION*65536 + \
     THP_AFE_HAL_SPEC_MINOR_VERSION*256 + \
     THP_AFE_HAL_SPEC_PATCH_VERSION)
/* defines the supported max number of scan frequencies */
#define THP_MAX_SCAN_FREQ_NUMBER_SUPPORTED     5
/* defines the supported max number of scan rates */
#define THP_MAX_SCAN_RATE_NUMBER_SUPPORTED     2

/* Error code of AFE */
typedef enum {
    THP_AFE_OK = 0,
    THP_AFE_EINVAL,                            /* invalid argument/parameter */
    THP_AFE_ENOMEM,                            /* out of memory */
    THP_AFE_EIO,                               /* driver/AFE error */
    THP_AFE_ESTATE,                            /* AFE HAL state error */
    THP_AFE_ETIMEOUT,                          /* get frame timeout */
    THP_AFE_EDATA,                             /* bad frame data */
    THP_AFE_EOTHER                             /* all other errors */
} THP_AFE_ERR_ENUM;

/* Error code of AFE Inspection */
typedef enum {
    THP_AFE_INSPECT_OK      = 0,               /* OK */
    THP_AFE_INSPECT_ESPI    = (1 << 0),        /* SPI communication error */
    THP_AFE_INSPECT_ERAW    = (1 << 1),        /* Raw data error */
    THP_AFE_INSPECT_ENOISE  = (1 << 2),        /* Noise error */
    THP_AFE_INSPECT_EOPEN   = (1 << 3),        /* Sensor open error */
    THP_AFE_INSPECT_ESHORT  = (1 << 4),        /* Sensor short error */
    THP_AFE_INSPECT_ERC     = (1 << 5),        /* Sensor RC error */
    THP_AFE_INSPECT_EPIN    = (1 << 6),        /* Errors of TSVDATSHDATRCSTATRCRQ and other PINs
                                                  when Report Rate Switching between 60 Hz and 120 Hz */
    THP_AFE_INSPECT_EOTHER  = (1 << 7)         /* All other errors */
} THP_AFE_INSPECT_ERR_ENUM;

/* Info of feature */
typedef enum {
    THP_AFE_FEATURE_NOT_SUPPORTED = 0,         /* feature is not supported */
    THP_AFE_FEATURE_SUPPORTED,                 /* Feature is supported but not automatically */
    THP_AFE_FEATURE_AUTO                       /* Feature is supported automatically */
} THP_AFE_FEATURE_ENUM;

/* Sensor architecture */
typedef enum {
    THP_AFE_SA_ONCELL = 1,                     /* On cell sensor */
    THP_AFE_SA_HYBRID_INCELL,                  /* Hybrid in cell sensor */
    THP_AFE_SA_FULL_INCELL                     /* Full in cell sensor */
} THP_AFE_SENSOR_ARCH_ENUM;

/* Sensor pattern */
typedef enum {
    THP_AFE_SP_SSD = 1,                        /* SSD sensor pattern */
    THP_AFE_SP_DSD,                            /* DSD sensor pattern */
    THP_AFE_SP_MH3,                            /* MH3 sensor pattern */
    THP_AFE_SP_PE1,                            /* PE1 sensor pattern */
    THP_AFE_SP_PE2,                            /* PE2 sensor pattern */
    THP_AFE_SP_AIT                             /* Full in cell self sensor pattern */
} THP_AFE_SENSOR_PATTERN_ENUM;

/* AFE status */
typedef enum {
    THP_AFE_STATUS_NONE = 0,                   /* On cell sensor */
    THP_AFE_STATUS_IDLE_MODE = (1 << 0),       /* Indicate AFE is running in IDLE mode */
    THP_AFE_STATUS_ACTIVE_MODE = (1 << 1),     /* Indicate AFE is running in Active mode */
    THP_AFE_STATUS_FREQ_SHIFT_DONE = (1 << 2), /* Indicate frequency shift has done */
    THP_AFE_STATUS_CALIBRATION_DONE = (1 << 3), /* Indicate calibration has done */
    THP_AFE_STATUS_GESTURE_DETECTED = (1 << 4), /* Indicate wakeup gesture is detected */
    THP_AFE_STATUS_ALL_FREQ_NOISY = (1 << 5),  /* Indicate all scan frequencies are noisy */
    THP_AFE_STATUS_SOS = (1 << 6)                /* Indicate AFE HAL run into unknown state
                                                    and can¡¯t recover by itself,
                                                    need help from caller which will normally reset AFE HAL */
} THP_AFE_STATUS_ENUM;

/* Information about the AFE and AFE library */
typedef struct {
    char vendor_name[32];                      /* 32 byte is set for Vendor name */
    char product_name[32];                     /* 32 byte is set for Produce name */
    char version[32];                          /* 32 byte is set for AFE version */
} THP_AFE_INFO_STRUCT;

/* Capabilities of the AFE */
typedef struct {
    uint16_t num_col;                          /* Number of sensors along column */
    uint16_t num_row;                          /* Number of sensors along row */
    uint8_t num_button;                        /* Number of buttons */
    uint8_t rx_direction;                      /* Direction of rx sensor:
                                                  0: rx is along column direction
                                                  1: rx is along row direction */
    uint8_t rx_channel;                        /* Number of rx channel supported by silicon */
    uint8_t rx_slot_layout;                    /* Layout of rx slot;
                                                  rx slot indicates the number of scan to finish all rx sensor scan
                                                  which equal to numRxSensor/numRxChannel normally;
                                                  0: normal layout, the rx sensors in the same rx slot
                                                  is physically grouped;
                                                  1: interlace layout, the rx sensors in the same rx slot
                                                  is interlaced instead of being physically grouped;
                                                  In case of numRxChannel >= numRxSensor, the layout should be
                                                  always normal; */
    uint16_t pitch_size_um;                    /* sensor pitch size in um */
    uint8_t num_scan_freq;                     /* Number of frequencies for hopping */
    uint16_t scan_freq[THP_MAX_SCAN_FREQ_NUMBER_SUPPORTED]; /* Array to hold all the scan frequencies,
                                                               for unused unit, set to 0; */
    uint8_t num_scan_rate;                     /* Number of scan rate choices in active mode;
                                                  for example: 60Hz and 120Hz are both supported,
                                                  then the num_active_scan_rate is 2; */
    uint16_t scan_rate[THP_MAX_SCAN_RATE_NUMBER_SUPPORTED]; /* Array to hold all the scan rates,
                                                  for unused unit, set to 0; */
    THP_AFE_FEATURE_ENUM feature_freq_hop;     /* Info of frequency hopping feature */
    THP_AFE_FEATURE_ENUM feature_calibration;  /* Info of calibration feature */
    THP_AFE_FEATURE_ENUM feature_wakeup_gesture; /* Info of wakeup gesture feature */
    THP_AFE_SENSOR_ARCH_ENUM sensor_arch;      /* Sensor Architecture */
    THP_AFE_SENSOR_PATTERN_ENUM sensor_pattern; /* Sensor Pattern */
} THP_AFE_HW_CAP_STRUCT;

#define __AFE_HAL_TEE_BUILD__
/* Frame data structure */
#ifndef __AFE_HAL_TEE_BUILD__
typedef struct timeval TIMEVAL_STRUCT;
#else
typedef struct {
    uint32_t seconds;
    uint32_t millis;
} TEE_Times;
#define TIMEVAL_STRUCT TEE_Times
#endif

typedef struct {
    TIMEVAL_STRUCT time_stamp;                 /* time_stamp records the system timeval info which could be
                                                  obtained from system */
    uint16_t frame_index;                      /* frame index, start from 0 after reset and should be increased 1 by 1
                                                  for each frame */
    uint16_t* grid_data;                       /* pointer to grid data, which could be mutual data or self data in
                                                  full incell architecture; data format: [row][col], col first, then row
                                                  col/row is defined in THP_AFE_HW_CAP_STRUCT
                                                  if no grid data available, the value should be set to NULL */
    uint16_t* line_data;                       /* pointer to line data, which could be self data or others;
                                                  data format: [row+col], col first, then row
                                                  col/row is defined in THP_AFE_HW_CAP_STRUCT
                                                  if no line data available, the value should be set to NULL */
    uint16_t* button_data;                     /* pointer to button data
                                                  the length of button data is defined in THP_AFE_HW_CAP_STRUCT;
                                                  if no button data available, the value should be set to NULL */
    uint16_t scan_freq;                        /* Current scan frequency, unit in KHz */
    uint8_t scan_rate;                         /* Current scan rate, unit in Hz */
    THP_AFE_STATUS_ENUM status;                /* Status of AFE */
} THP_AFE_FRAME_DATA_STRUCT;


typedef struct {
    int status;
    int x;
    int y;
    int area;
    int pressure;
    int orientation;
    int major;
    int minor;
    int event;
    unsigned int cur_pid;
} ts_tui_finger;

struct tsa_version_info {
    int algo_major;
    int algo_minor;
    int algo_build;
    int jdi_algo_version;
    // string algo_project_name;
};


#define get_bit(flag, bit)   ((flag) & (bit))
#define set_bit(flag, bit)\
    do {\
        (flag) |= (bit);\
    } while (0)

#define unset_bit(flag, bit)\
    do {\
        (flag) &= ~(bit);\
    } while (0)


#define to_kilo(value)                           ((value) * 1000)
#define second_to_ms(value)                      to_kilo(value)                        /* time function, unit is ms */
#define millisecond_to_us(value)                 to_kilo(value)                        /* time function, unit is us */
#define second_to_us(value)                      millisecond_to_us(to_kilo(value))     /* time function, unit is us */
#define ONE_KILO                                 to_kilo(1)
#define APTOUCH_DAEMON_INIT_LOOP_WAIT_US         millisecond_to_us(100)
#define APTOUCH_DAEMON_GETFRAME_LOOP_WAIT_US     millisecond_to_us(100)
#define timeval_to_ms(tv)                        (to_kilo(tv.seconds) + (tv.millis) / ONE_KILO)


typedef  struct {
    uint32_t (*thp_afe_hal_spec_version)(void);
    uint8_t (*thp_afe_hal_spec_major_version)(void);
    uint8_t (*thp_afe_hal_spec_minor_version)(void);
    uint8_t (*thp_afe_hal_spec_patch_version)(void);
    THP_AFE_ERR_ENUM (*thp_afe_open)(void);
    THP_AFE_ERR_ENUM (*thp_afe_open_project)(const char* projID);
    THP_AFE_ERR_ENUM (*thp_afe_close)(void);
    THP_AFE_ERR_ENUM (*thp_afe_start)(void);
    THP_AFE_ERR_ENUM (*thp_afe_stop)(void);
    THP_AFE_ERR_ENUM (*thp_afe_screen_off)(void);
    THP_AFE_ERR_ENUM (*thp_afe_screen_on)(void);
    THP_AFE_INFO_STRUCT* (*thp_afe_get_info)(void);
    THP_AFE_HW_CAP_STRUCT* (*thp_afe_get_hw_cap)(void);
    THP_AFE_FRAME_DATA_STRUCT* (*thp_afe_get_frame)(void);
    THP_AFE_ERR_ENUM (*thp_afe_start_freq_shift)(void);
    THP_AFE_ERR_ENUM (*thp_afe_set_freq_point_min_hold_time)(uint16_t minholdtime);
    THP_AFE_ERR_ENUM (*thp_afe_reset_freq_state)(void);
    THP_AFE_ERR_ENUM (*thp_afe_start_calibration)(void);

    THP_AFE_ERR_ENUM (*thp_afe_set_calib_data_callback_func)
    (THP_AFE_ERR_ENUM(*calibDataWriteCallback)(void* dataPtr, uint32_t dataLen),
     THP_AFE_ERR_ENUM(*calibDataReadCallback)(void* dataPtr, uint32_t dataLen));

    THP_AFE_ERR_ENUM (*thp_afe_clear_status)(THP_AFE_STATUS_ENUM status);
    THP_AFE_ERR_ENUM (*thp_afe_set_baseline_update_interval)(uint16_t interval);
    THP_AFE_ERR_ENUM (*thp_afe_set_idle_touch_threshold)(uint16_t threshold);
    THP_AFE_ERR_ENUM (*thp_afe_set_idle_scan_rate)(uint8_t rate);
    THP_AFE_ERR_ENUM (*thp_afe_enter_idle)(void);
    THP_AFE_ERR_ENUM (*thp_afe_force_exit_idle)(void);
    THP_AFE_ERR_ENUM (*thp_afe_force_to_freq_point)(uint8_t index);
    THP_AFE_ERR_ENUM (*thp_afe_force_to_scan_rate)(uint8_t index);
    THP_AFE_ERR_ENUM (*thp_afe_set_log_callback_func)(void(*log_func)(const char*));
    THP_AFE_ERR_ENUM (*thp_afe_set_log_level)(uint8_t log_level);
    THP_AFE_ERR_ENUM (*thp_afe_enable_wakeup_gesture)(void);
    THP_AFE_ERR_ENUM (*thp_afe_disable_wakeup_gesture)(void);
    THP_AFE_ERR_ENUM (*thp_afe_set_wakeup_gesture_scan_rate)(uint8_t rate);
    uint32_t (*thp_afe_inspect)(void);
    THP_AFE_ERR_ENUM (*thp_afe_enter_tui)(void);
    THP_AFE_ERR_ENUM (*thp_afe_exit_tui)(void);
} thp_afe_api;

int thp_ta_init(void);
int  thp_ta_deinit(void);
int  tui_ta_get_tpdata_thp(ts_tui_finger* data);
int thp_afe_wrapper_init(const char* projectId);
int thp_init(void);
int thp_deinit(void);
int tui_get_tpdata_thp(ts_tui_finger* data);
#ifdef __cplusplus
}
#endif

#endif /* __THP_AFE_HAL_H_ */

