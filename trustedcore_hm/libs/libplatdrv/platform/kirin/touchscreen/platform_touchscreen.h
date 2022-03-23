/*
 * thp tui driver
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: thp tui driver
 * Author: lijie
 * Create: 2018-12-24
 */
#ifndef _PLATFORM_TOUCHSCREEN_
#define _PLATFORM_TOUCHSCREEN_

#define NO_ERR 0
#define TUI_ERR (-1)
#define TS_TUI_MAX_FINGER 10
#define EV_ABS 0x03
#define TS_FINGER_RELEASE (1 << 5)
#define TS_FINGER_PRESS (1 << 6)
#define THP_PROJECT_ID_LEN 10
#define MAX_FRAME_LEN 4096
#define ERROR (-1)

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260)
#define I2C_ADDR 0xFDF0B000
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990)
#define I2C_ADDR 0xFA04F000
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
#define I2C_ADDR 0xFA04F000
#else
#define I2C_ADDR 0xFFD73000
#endif

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660)
#define GPIO_TP_SPI_CS 18
#define TP_SPI_BUS_ADDR 0xfdf08000
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260)
#define GPIO_TP_SPI_CS 10
#define TP_SPI_BUS_ADDR 0xfdf08000
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670)
#define GPIO_TP_SPI_CS 147
#define TP_SPI_BUS_ADDR 0xfff2a000
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO)
#define GPIO_TP_SPI_CS 227
#define TP_SPI_BUS_ADDR 0xfdf08000
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990)
#define GPIO_TP_SPI_CS 177
#define TP_SPI_BUS_ADDR 0xfa89f000
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
#define GPIO_TP_SPI_CS 177
#define TP_SPI_BUS_ADDR 0xfa89f000
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
#define GPIO_TP_SPI_CS 191
#define TP_SPI_BUS_ADDR 0xfa048000
#else /* WITH_CHIP_HI3680 */
#define GPIO_TP_SPI_CS 236
#define TP_SPI_BUS_ADDR 0xfff2a000
#endif

#define TOUCH_SLAVE_ADDR 0X70

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260)
#define TS_GPIO_NUM 210
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO)
#define TS_GPIO_NUM 207
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990)
#define TS_GPIO_NUM 172
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
#define TS_GPIO_NUM 178
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
#define TS_GPIO_NUM 197
#else
#define TS_GPIO_NUM 212
#endif

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660)
#define TS_GPIO_IRQ 245
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670)
#define TS_GPIO_IRQ 243
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680)
#define TS_GPIO_IRQ 282
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990)
#define TS_GPIO_IRQ 304 /* GPIO_008_SE */
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260)
#define TS_GPIO_IRQ 240
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO)
#define TS_GPIO_IRQ 284
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
#define TS_GPIO_IRQ 305 /* GPIO_009_SE */
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
#define TS_GPIO_IRQ 307 /* GPIO_011_SE */
#else
#define TS_GPIO_IRQ 192
#endif

#define MASK_16BIT 0xFFFF
#define MASK_8BIT 0xFF
#define MASK_7BIT 0x7F
#define MASK_6BIT 0x3F
#define MASK_5BIT 0x1F
#define MASK_4BIT 0x0F
#define MASK_3BIT 0x07
#define MASK_2BIT 0x03
#define MASK_1BIT 0x01

#ifndef __TS_TUI_FINGER
/* struct funcs */
struct ts_tui_finger {
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
};

struct ts_tui_finger_shb {
    int status;
    int x;
    int y;
};

#define __TS_TUI_FINGER
#endif

/* lint -e754 -esym(754,*) */
struct ts_tui_fingers {
    struct ts_tui_finger fingers[TS_TUI_MAX_FINGER];
    int cur_finger_number;
    unsigned int gesture_wakeup_value;
    unsigned int special_button_key;
    unsigned int special_button_flag;
};
/* lint -e754 +esym(754,*) */

#define NOTIFY_DATA_RESERVED 32
struct tp_notify_data_t {
    int irq_type;
    union {
        struct ts_tui_fingers tui_notify_data;
        int reserved[NOTIFY_DATA_RESERVED];
    };
};

/* NOTICE: any change should kee align with thp_afe_driver.c */
#define TS_GET_FRAME 0x1
#define TS_SPI_SYNC 0x2
#define TS_IRQ_CTL 0x3
#define TS_GET_PRO_ID 0x4
#define TS_SYNC_FRAME 0x5

struct effective_fingers {
    int y0;
    int y1;
};

struct ts_frame_data {
    unsigned int size;
    char buf[MAX_FRAME_LEN];
};

#define MAX_REG_BUF_SIZE (MAX_FRAME_LEN / 2)
struct ts_reg_data {
    unsigned int size;
    unsigned char txbuf[MAX_REG_BUF_SIZE];
    unsigned char rxbuf[MAX_REG_BUF_SIZE];
};

struct ts_info {
    union __ts_ioctl_data {
        struct ts_frame_data ts_frame_info;
        struct ts_reg_data reg_data;
        char project_id[THP_PROJECT_ID_LEN + 1];
    } ts_ioctl_data;
    unsigned char reserved;
};

struct tee_thp_frame_buff {
    unsigned char flag; /* store 1 send set 0 */
    unsigned char revbuff[MAX_FRAME_LEN];
};

#define TP_TUI_NEW_IRQ_SUPPORT 1
#define TP_TUI_NEW_IRQ_MASK 0x1
struct reportid {
    u8 t100_reportid_min;
    u8 t100_reportid_max;
};
struct mxt_tui_data {
    char device_name[THP_PROJECT_ID_LEN + 1];
    u8 max_reportid;
    u16 t5_address;
    u8 t5_msg_size;
    union {
        u16 t44_address;
        /* tui_special_feature_support's bit0: set new irq gpio support */
        unsigned short tui_special_feature_support;
    };
    union {
        u16 t100_address;
        unsigned short tui_irq_gpio;
    };
    union {
        struct reportid reportid;
        u16 tui_irq_num;
    };
    u16 addr;
};
int ts_tui_algo_t1(struct ts_tui_fingers *in_info, struct ts_tui_fingers *out_info);
#endif
