/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: synatics tp driver
 * Author:
 * Create: 2012-01-01
 */

#include <legacy_mem_ext.h> /* SRE_MemAlloc */
#include <dlist.h>
#include <mem_ops.h>
#include "sre_sys.h"
#include "i2c.h"
#include "gpio.h"
#include "mem_page_ops.h"
#include "libhwsecurec/securec.h"
#include "platform_touchscreen.h"
#include "hisi_tui_touchscreen.h"
#include "tui_panel.h"

extern int g_frame_max_len;
extern struct tee_thp_frame_buff g_tee_tp_buff;

#define TP_QUERY_TIMES 10
#define F12_FINGERS_TO_SUPPORT 10
#define PDT_PROPS 0x00EF
#define PDT_START 0x00E9
#define PDT_END 0x000A
#define PDT_ENTRY_SIZE 0x0006
#define PAGES_TO_SERVICE 10
#define MAX_INTR_REGISTERS 4
#define MAX_STR_LEN 32
#define F01_DATA_BASE_ADDR 0x04
#define F12_DATA_BASE_ADDR 0x06
#define DATA1_OFFSET 0
#define SYNAPTICS_RMI4_F01 0x01
#define SYNAPTICS_RMI4_F11 0x11
#define SYNAPTICS_RMI4_F12 0x12
#define SYNAPTICS_RMI4_F1A 0x1a
#define SYNAPTICS_RMI4_F34 0x34
#define SYNAPTICS_RMI4_F51 0x51
#define SYNAPTICS_RMI4_F54 0x54
#define SYNAPTICS_RMI4_F55 0x55
#define SYNAPTICS_INTR_REG_NUM 1
#define SYNAPTICS_F12_INTR_MASK 0x04
#define PAGE_TUI_SELECT_LEN 2
#define FLIX_X 1
#define FLIX_Y 1
#define SENSOR_MAX_X 1080
#define SENSOR_MAX_Y 1920
#define FINGERS_TO_PROCESS 10
#define SIZE_OF_2D_DATA 8

struct synaptics_rmi4_f12_extra_data {
    unsigned char data1_offset;
    unsigned char data15_offset;
    unsigned char data15_size;
    unsigned char data15_data[(F12_FINGERS_TO_SUPPORT + OFFSET_BYTE7) / 8]; /* data size 8 */
};

struct synaptics_rmi4_f12_query_8 {
    union {
        struct {
            unsigned char size_of_query9;
            struct {
                unsigned char data0_is_present : 1;
                unsigned char data1_is_present : 1;
                unsigned char data2_is_present : 1;
                unsigned char data3_is_present : 1;
                unsigned char data4_is_present : 1;
                unsigned char data5_is_present : 1;
                unsigned char data6_is_present : 1;
                unsigned char data7_is_present : 1;
            };
            struct {
                unsigned char data8_is_present : 1;
                unsigned char data9_is_present : 1;
                unsigned char data10_is_present : 1;
                unsigned char data11_is_present : 1;
                unsigned char data12_is_present : 1;
                unsigned char data13_is_present : 1;
                unsigned char data14_is_present : 1;
                unsigned char data15_is_present : 1;
            };
        };
        unsigned char data[OFFSET_BYTE3];
    };
};

/*
 * struct synaptics_rmi4_fn_desc - function descriptor fields in PDT
 * @query_base_addr: base address for query registers
 * @cmd_base_addr: base address for command registers
 * @ctrl_base_addr: base address for control registers
 * @data_base_addr: base address for data registers
 * @intr_src_count: number of interrupt sources
 * @fn_number: function number
 */
struct synaptics_rmi4_fn_desc {
    union {
        struct {
            unsigned char query_base_addr;
            unsigned char cmd_base_addr;
            unsigned char ctrl_base_addr;
            unsigned char data_base_addr;
            unsigned char intr_src_count : 3;
            unsigned char reserved_1 : 2;
            unsigned char fn_version : 2;
            unsigned char reserved_2 : 1;
            unsigned char fn_number;
        };
        unsigned char data[OFFSET_BYTE6];
    };
};

/*
 * synaptics_rmi4_fn_full_addr - full 16-bit base addresses
 * @query_base: 16-bit base address for query registers
 * @cmd_base: 16-bit base address for data registers
 * @ctrl_base: 16-bit base address for command registers
 * @data_base: 16-bit base address for control registers
 */
struct synaptics_rmi4_fn_full_addr {
    unsigned short query_base;
    unsigned short cmd_base;
    unsigned short ctrl_base;
    unsigned short data_base;
};

/*
 * struct synaptics_rmi4_fn - function handler data structure
 * @fn_number: function number
 * @num_of_data_sources: number of data sources
 * @num_of_data_points: maximum number of fingers supported
 * @size_of_data_register_block: data register block size
 * @data1_offset: offset to data1 register from data base address
 * @intr_reg_num: index to associated interrupt register
 * @intr_mask: interrupt mask
 * @full_addr: full 16-bit base addresses of function registers
 * @link: linked list for function handlers
 * @data_size: size of private data
 * @data: pointer to private data
 */
struct synaptics_rmi4_fn {
    unsigned char fn_number;
    unsigned char num_of_data_sources;
    unsigned char num_of_data_points;
    unsigned char size_of_data_register_block;
    unsigned char data1_offset;
    unsigned char intr_reg_num;
    unsigned char intr_mask;
    struct synaptics_rmi4_fn_full_addr full_addr;
    struct dlist_node link;
    int data_size;
    void *data;
    void *extra;
};

unsigned char ts_tui_current_page = MASK_8BIT;

static struct synaptics_rmi4_fn_desc rmi_fd_f01;
static struct synaptics_rmi4_fn *fhandler_f12 = NULL;
struct synaptics_tui_f12_finger_data {
    unsigned char object_type_and_status;
    unsigned char x_lsb;
    unsigned char x_msb;
    unsigned char y_lsb;
    unsigned char y_msb;
    unsigned char z;
    unsigned char wx;
    unsigned char wy;
};

static int synaptics_rmi4_query_device();
/*
 * ts_synaptics_set_page()
 *
 * Called by ts_synaptics_i2c_read() and ts_synaptics_i2c_write().
 *
 * This function writes to the page select register to switch to the
 * assigned page.
 */
static int ts_synaptics_set_page(unsigned int address)
{
    int retval = NO_ERR;
    unsigned char buf[PAGE_TUI_SELECT_LEN];
    unsigned char page;

    page = ((address >> OFFSET_BYTE8) & MASK_8BIT);
    if (page != ts_tui_current_page) {
        buf[0] = MASK_8BIT;
        buf[1] = page;
        retval = hisi_i2c_write(I2C_ADDR, buf, PAGE_TUI_SELECT_LEN, TOUCH_SLAVE_ADDR);
        if (retval != NO_ERR)
            TP_LOG_ERR("bus_write failed\n");
        else
            ts_tui_current_page = page;
    } else {
        return PAGE_TUI_SELECT_LEN;
    }
    return (retval == NO_ERR) ? PAGE_TUI_SELECT_LEN : -5;  /* synaptics errorno -5 */
}

/*
 * synaptics_rmi4_i2c_read()
 *
 * Called by various functions in this driver, and also exported to
 * other expansion Function modules such as rmi_dev.
 *
 * This function reads data of an arbitrary length from the sensor,
 * starting from an assigned register address of the sensor, via I2C
 * with a retry mechanism.
 */
static int ts_synaptics_i2c_read(unsigned short addr, unsigned char *data, unsigned short length)
{
    int retval;
    unsigned char reg_addr = addr & MASK_8BIT;

    if (data == NULL)
        return ERROR;

    data[0] = reg_addr;

    retval = ts_synaptics_set_page(addr);
    if (retval != PAGE_TUI_SELECT_LEN) {
        TP_LOG_ERR("error, retval != PAGE_TUI_SELECT_LEN\n");
        goto exit;
    }

    retval = hisi_i2c_read(I2C_ADDR, data, length, TOUCH_SLAVE_ADDR);
    if (retval < 0) {
        TP_LOG_ERR("error, bus read failed, retval  = %d\n", retval);
        goto exit;
    }

exit:
    return retval;
}

/*
 * ts_tui_f12_abs_report()
 *
 *
 * This function reads the Function $12 data registers, determines the
 * status of each finger supported by the Function, processes any
 * necessary coordinate manipulation, reports the finger data to
 * the input subsystem, and returns the number of fingers detected.
 */
static void ts_tui_f12_abs_report(struct ts_tui_fingers *data_info)
{
    int retval;
    unsigned char touch_count_num = 0; /* number of touch points */
    unsigned char finger;
    unsigned char finger_status;
    unsigned short data_addr;
    unsigned char *f12_data = NULL;
    struct synaptics_tui_f12_finger_data *data = NULL;
    struct synaptics_tui_f12_finger_data *finger_data = NULL;
    struct ts_tui_fingers *info = NULL;
    struct synaptics_rmi4_f12_extra_data *extra_data = NULL;

    if (data_info == NULL)
        return;

    data_addr = fhandler_f12->full_addr.data_base;
    extra_data = (struct synaptics_rmi4_f12_extra_data *)fhandler_f12->extra;
    f12_data = (unsigned char *)SRE_MemAlloc(0, 0, FINGERS_TO_PROCESS * SIZE_OF_2D_DATA);
    if (f12_data == NULL) {
        TP_LOG_ERR("Failed to alloc mem for f12_data!\n");
        return;
    }

    info = (struct ts_tui_fingers *)SRE_MemAlloc(0, 0, sizeof(*info));
    if (info == NULL) {
        TP_LOG_ERR("Failed to alloc mem for info!\n");
        SRE_MemFree(0, f12_data);
        return;
    }

    if (memset_s(f12_data, FINGERS_TO_PROCESS * SIZE_OF_2D_DATA, 0, FINGERS_TO_PROCESS * SIZE_OF_2D_DATA))
        TP_LOG_ERR("memset_s error\n");
    if (memset_s(info, sizeof(*info), 0, sizeof(*info)))
        TP_LOG_ERR("memset_s error\n");
    retval =
        ts_synaptics_i2c_read(data_addr + extra_data->data1_offset, f12_data, FINGERS_TO_PROCESS * SIZE_OF_2D_DATA);
    if (retval < 0) {
        TP_LOG_ERR("Failed to read data,retval: %d,\n", retval);
        SRE_MemFree(0, f12_data);
        SRE_MemFree(0, info);
        return;
    }

    data = (struct synaptics_tui_f12_finger_data *)f12_data; /* lint !e826 */
    for (finger = 0; finger < FINGERS_TO_PROCESS; finger++) {
        finger_data = data + finger;
        finger_status = finger_data->object_type_and_status;

        /*
         * Each 2-bit finger status field represents the following:
         * 00 = finger not present
         * 01 = finger present and data accurate
         * 10 = finger present but data may be inaccurate
         * 11 = reserved
         */
        if (finger_status) {
            info->fingers[finger].status = finger_status;
            info->fingers[finger].x = (finger_data->x_msb << OFFSET_BYTE8) | (finger_data->x_lsb);
            info->fingers[finger].y = (finger_data->y_msb << OFFSET_BYTE8) | (finger_data->y_lsb);
            info->fingers[finger].major = finger_data->wx;
            info->fingers[finger].minor = finger_data->wy;
            info->fingers[finger].pressure = finger_data->z;
            touch_count_num++;
            TP_LOG_ERR("Finger %d:\n status = %d\n wx = %d\n wy = %d\n z = %d\n", finger, finger_status,
                finger_data->wx, finger_data->wy, finger_data->z);
        }
    }
    info->cur_finger_number = touch_count_num;

    ts_tui_algo_t1(info, data_info);

    TP_LOG_DEBUG("f12_abs_report, touch_count = %d\n", touch_count_num);
    SRE_MemFree(0, f12_data);
    SRE_MemFree(0, info);
}

int synaptics_get_data(struct ts_tui_fingers *report_data)
{
    int retval;
    unsigned char intr[MAX_INTR_REGISTERS] = {0};

    if (report_data == NULL)
        return ERROR;

    retval = ts_synaptics_i2c_read(rmi_fd_f01.data_base_addr + 1, intr, SYNAPTICS_INTR_REG_NUM);
    TP_LOG_DEBUG("get interrupts status information ok intr[0] = %d\n", intr[0]);
    if (retval < 0) {
        TP_LOG_ERR("get interrupts status information failed, retval = %d\n", retval);
        return retval;
    }

    if (SYNAPTICS_F12_INTR_MASK & intr[0]) {
        retval = ts_synaptics_i2c_read(rmi_fd_f01.data_base_addr + 1, intr, SYNAPTICS_INTR_REG_NUM);
        if (retval < 0) {
            TP_LOG_ERR("get interrupts status information failed, retval = %d\n", retval);
            return retval;
        }
        ts_tui_f12_abs_report(report_data);
    }
    return 0;
}

int synaptics_device_init(void)
{
    int i = 0;

    while (i < TP_QUERY_TIMES && fhandler_f12 == NULL) {
        synaptics_rmi4_query_device();
        SRE_DelayMs(10); /* delay 10ms to wait device init */
        i++;
    }
    TP_LOG_DEBUG("synaptics_rmi4_query_device times=%d\n", i);
    if (i == TP_QUERY_TIMES)
        return ERROR;
    return 0;
}

static struct synaptics_rmi4_fn *synaptics_rmi4_alloc_fh(struct synaptics_rmi4_fn_desc *rmi_fd, int page_number)
{
    struct synaptics_rmi4_fn *fhandler = NULL;
    int ret;

    if (rmi_fd == NULL)
        return NULL;
    fhandler = (struct synaptics_rmi4_fn *)SRE_MemAlloc(0, 0, sizeof(struct synaptics_rmi4_fn));
    if (!fhandler) {
        TP_LOG_DEBUG("Failed to alloc memory for fhandler\n");
        return NULL;
    }
    ret = memset_s(fhandler, sizeof(struct synaptics_rmi4_fn), 0, sizeof(struct synaptics_rmi4_fn));
    if (ret)
        TP_LOG_ERR("memset_s error: ret=[%d]\n", ret);

    unsigned int page_number_shift = (unsigned int)page_number;

    fhandler->full_addr.data_base = (unsigned short)(rmi_fd->data_base_addr | (page_number_shift << OFFSET_BYTE8));
    fhandler->full_addr.ctrl_base = (unsigned short)(rmi_fd->ctrl_base_addr | (page_number_shift << OFFSET_BYTE8));
    fhandler->full_addr.cmd_base = (unsigned short)(rmi_fd->cmd_base_addr | (page_number_shift << OFFSET_BYTE8));
    fhandler->full_addr.query_base = (unsigned short)(rmi_fd->query_base_addr | (page_number_shift << OFFSET_BYTE8));
    fhandler->fn_number = rmi_fd->fn_number;
    TP_LOG_DEBUG("handler number is %d, it's data_base_addr = %d, ctrl_base_addr = %d, cmd_base_addr = "
                 "%d,query_base_addr = %d, page_number = %d\n",
        rmi_fd->fn_number, rmi_fd->data_base_addr, rmi_fd->ctrl_base_addr, rmi_fd->cmd_base_addr,
        rmi_fd->query_base_addr, page_number);
    return fhandler;
}

/*
 *
 * Called by synaptics_rmi4_query_device().
 *
 * This funtion parses information from the Function 12 registers and
 * determines the number of fingers supported, offset to the data1
 * register, x and y data ranges, offset to the associated interrupt
 * status register, interrupt bit mask, and allocates memory resources
 * for finger data acquisition.
 */
static int synaptics_rmi4_f12_init(struct synaptics_rmi4_fn *fhandler, struct synaptics_rmi4_fn_desc *fd)
{
    int retval;
    struct synaptics_rmi4_f12_extra_data *extra_data = NULL;
    unsigned char size_of_query8 = 0;
    struct synaptics_rmi4_f12_query_8 query_8;

    if ((fhandler == NULL) || (fd == NULL))
        return ERROR;

    fhandler->fn_number = fd->fn_number;
    fhandler->num_of_data_sources = fd->intr_src_count;
    fhandler->extra = (void *)SRE_MemAlloc(0, 0, sizeof(struct synaptics_rmi4_f12_extra_data));
    if (fhandler->extra == NULL) {
        TP_LOG_ERR("Failed to alloc memory for fhandler->extra\n");
        retval = -1;
        return retval;
    }
    retval = memset_s(fhandler->extra, sizeof(struct synaptics_rmi4_f12_extra_data), 0,
        sizeof(struct synaptics_rmi4_f12_extra_data));
    if (retval)
        TP_LOG_ERR("memset_s error: ret=[%d]\n", retval);

    extra_data = (struct synaptics_rmi4_f12_extra_data *)fhandler->extra;

    retval = ts_synaptics_i2c_read(fhandler->full_addr.query_base + 7, /* offset 7 bit to read f12 */
        &size_of_query8, sizeof(size_of_query8));
    if (retval < 0) {
        TP_LOG_ERR("Failed to read f12 ->full_addr.query_base = %d,here is +7\n", fhandler->full_addr.query_base);
        return retval;
    }
    if (size_of_query8 > OFFSET_BYTE3)
        size_of_query8 = OFFSET_BYTE3;
    retval = ts_synaptics_i2c_read(fhandler->full_addr.query_base + 8, /* offset 8 bit to read f12 */
        query_8.data, size_of_query8);
    if (retval < 0) {
        TP_LOG_ERR("Failed to read f12 ->full_addr.query_base = %d,here is +8\n", fhandler->full_addr.query_base);
        return retval;
    }

    /* Determine the presence of the Data0 register */
    extra_data->data1_offset = query_8.data0_is_present;

    return retval;
}

/*
 * synaptics_rmi4_query_device()
 *
 * Called by synaptics_init_chip().
 *
 * This funtion scans the page description table, records the offsets
 * to the register types of Function $01, sets up the function handlers
 * for Function $11 and Function $12, determines the number of interrupt
 * sources from the sensor, adds valid Functions with data inputs to the
 * Function linked list, parses information from the query registers of
 * Function $01, and enables the interrupt sources from the valid Functions
 * with data inputs.
 */
static int synaptics_rmi4_query_device()
{
    int retval;
    unsigned char page_number;
    unsigned short pdt_entry_addr;
    struct synaptics_rmi4_fn_desc rmi_fd;

    /* Scan the page description tables of the pages to service */
    for (page_number = 0; page_number < PAGES_TO_SERVICE; page_number++) {
        for (pdt_entry_addr = PDT_START; pdt_entry_addr > PDT_END; pdt_entry_addr -= PDT_ENTRY_SIZE) {
            pdt_entry_addr |= (page_number << OFFSET_BYTE8);
            retval = ts_synaptics_i2c_read(pdt_entry_addr, (unsigned char *)&rmi_fd, sizeof(rmi_fd));
            if (retval < 0) {
                TP_LOG_ERR("read pdt_entry_addr = %d regiseter error happened\n", pdt_entry_addr);
                return retval;
            }

            if (rmi_fd.fn_number == 0) {
                TP_LOG_DEBUG("Reached end of PDT\n");
                break;
            }

            switch (rmi_fd.fn_number) {
            case SYNAPTICS_RMI4_F01:
                (void)memcpy_s(&rmi_fd_f01, sizeof(struct synaptics_rmi4_fn_desc), &rmi_fd,
                    sizeof(struct synaptics_rmi4_fn_desc));
                break;

            case SYNAPTICS_RMI4_F12:
                if (rmi_fd.intr_src_count == 0)
                    break;

                fhandler_f12 = synaptics_rmi4_alloc_fh(&rmi_fd, page_number);
                if (fhandler_f12 == NULL) {
                    TP_LOG_ERR("Failed to alloc for F%d\n", rmi_fd.fn_number);
                    retval = -1;
                    return retval;
                }
                retval = synaptics_rmi4_f12_init(fhandler_f12, &rmi_fd);
                if (retval < 0) {
                    TP_LOG_ERR("Failed to init f12 handler , retval = %d\n", retval);
                    return retval;
                }
                break;
            default:
                break;
            }
        }
    } /* lint !e850 */
    return retval;
}

void tui_synaptics_exit(void)
{
    if (fhandler_f12) {
        if (fhandler_f12->extra)
            SRE_MemFree(0, fhandler_f12->extra);
        SRE_MemFree(0, fhandler_f12);
        fhandler_f12 = NULL;
    }
}

/* thp */
enum status_code {
    STATUS_IDLE = 0x00,
    STATUS_OK = 0x01,
    STATUS_BUSY = 0x02,
    STATUS_CONTINUED_READ = 0x03,
    STATUS_RECEIVE_BUFFER_OVERFLOW = 0x0c,
    STATUS_PREVIOUS_COMMAND_PENDING = 0x0d,
    STATUS_NOT_IMPLEMENTED = 0x0e,
    STATUS_ERROR = 0x0f,
    STATUS_INVALID = 0xff,
};

enum report_type {
    REPORT_IDENTIFY = 0x10,
    REPORT_TOUCH = 0x11,
    REPORT_DELTA = 0x12,
    REPORT_RAW = 0x13,
    REPORT_PRINTF = 0x82,
    REPORT_STATUS = 0x83,
    REPORT_FRAME = 0xC0,
    REPORT_HDL = 0xfe,
};
int ts_syn_init(void)
{
    TP_LOG_ERR("ts_syn_init....\n");
    return 0;
}
int ts_syn_get_frame(struct ts_tui_fingers *report_data)
{
#define DATA_LEN 4
#define FRAME_LENGTH 1080 /* (2*18*30) */
#define MESSAGE_MARKER 0xa5
#define FIRST_FRAME_USEFULL_LEN 2
    unsigned char buff[DATA_LEN] = { 0, 0, 0, 0 };
    unsigned char data[DATA_LEN] = {0};
    unsigned int length;
    int retval;
    (void)report_data;

    retval = ts_spi_sync(DATA_LEN, &buff[0], &data[0]); /* read length */
    if (retval < 0) {
        TP_LOG_ERR("%s: Failed to read length\n", __func__);
        return ERROR;
    }
    if (data[1] == 0xFF) {
        TP_LOG_ERR("%s: should ignore this irq.\n", __func__);
        return ERROR;
    }
    if (data[0] != MESSAGE_MARKER) {
        TP_LOG_ERR("%s: incorrect marker: 0x%02x\n", __func__, data[0]);
        if (data[1] == STATUS_CONTINUED_READ) {
            /* just in case */
            TP_LOG_ERR("%s: continued Read MAX_FRAME_LEN\n", __func__);
            /* drop one transaction */
            ts_spi_sync(MAX_FRAME_LEN, &buff[0], &g_tee_tp_buff.revbuff[0]);
        }
        return ERROR;
    }

    length = (data[OFFSET_BYTE3] << OFFSET_BYTE8) | data[OFFSET_BYTE2]; /* calculate frame length */
    if (length > (MAX_FRAME_LEN - FIRST_FRAME_USEFULL_LEN)) {
        TP_LOG_ERR("%s: out of length.\n", __func__);
        length = MAX_FRAME_LEN - FIRST_FRAME_USEFULL_LEN;
    }
    if (length) {
        retval = ts_spi_sync(length + FIRST_FRAME_USEFULL_LEN, &buff[0],
            &g_tee_tp_buff.revbuff[FIRST_FRAME_USEFULL_LEN]); /* read packet */
        if (retval < 0) {
            TP_LOG_ERR("%s: Failed to read length\n", __func__);
            return ERROR;
        }
    }

    retval = memcpy_s(&g_tee_tp_buff.revbuff[0], DATA_LEN, data, DATA_LEN);
    if (retval)
        TP_LOG_ERR("%s: Failed to memcpy data\n", __func__);

    if (g_tee_tp_buff.flag == 0)
        g_tee_tp_buff.flag = 1;

    return NO_ERR;
}