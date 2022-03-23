/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2050. All rights reserved.
 * Description: synatics_tcm tp driver
 * Author: Chen puwang
 * Create: 2020-04-20
 */

#include <legacy_mem_ext.h>
#include <mem_ops.h>
#include "sre_sys.h"
#include "i2c.h"
#include "gpio.h"
#include "mem_page_ops.h"
#include "../../../kirin/spi/spi.h"
#include "libhwsecurec/securec.h"
#include "tui_panel.h"
#include "platform_touchscreen.h"
#include "hisi_tui_touchscreen.h"

#define FIXED_READ_LENGTH 256
#define MESSAGE_HEADER_SIZE 4
#define MESSAGE_MARKER 0xa5
#define MESSAGE_PADDING 0x5a
#define PDT_START_ADDR 0x00e9
#define PDT_END_ADDR 0x00ee
#define UBL_FN_NUMBER 0x35
#define READ_RETRY_US 7000
#define READ_RETRY_MS 7
#define READ_CFG_CMD_SIZE 3
#define TOUCH_REPORT_CONFIG_SIZE 128
#define MSG_STATUS_SIZE 2
#define BIT_PER_BYTE 8
#define BIT_PER_WORD 32
#define MAX_RETRY_NUM 5
#define SYNA_I3C_ADDR 0x70
#define SYNA_ERR_STATUS (-1)
#define TP_TUI_BUS_TYPE_MASK 0x02

struct syna_tcm_message_header {
    unsigned char marker;
    unsigned char code;
    unsigned char length[2]; /* chip header length 2 char */
};

struct syna_tcm_buffer {
    bool clone;
    unsigned char *buf;
    unsigned int buf_size;
    unsigned int data_length;
};

struct syna_tcm_report {
    unsigned char id;
    struct syna_tcm_buffer buffer;
};

struct object_data {
    unsigned char status;
    unsigned int x_pos;
    unsigned int y_pos;
    unsigned int z;
    unsigned int x_width;
    unsigned int y_width;
};

struct syna_tcm_hcd {
    unsigned char status_report_code;
    unsigned int payload_length;
    struct syna_tcm_buffer config;
    struct syna_tcm_report report;
    struct object_data object_data[TOUCH_MAX_FINGER_NUM];
    struct syna_tcm_buffer temp;
    unsigned char prev_status[TOUCH_MAX_FINGER_NUM];
    unsigned int num_of_active_objects;
    unsigned int num_of_finger;
    unsigned int rd_chunk_size;
};

enum touch_status {
    LIFT = 0,
    FINGER = 1,
    GLOVED_FINGER = 2,
    NOP = -1,
};

enum status_code {
    STATUS_IDLE = 0x00,
    STATUS_OK = 0x01,
    STATUS_BUSY = 0x02,
    STATUS_CONTINUED_READ = 0x03,
    STATUS_NOT_EXECUTED_IN_DEEP_SLEEP = 0x0b,
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
    REPORT_STATUS = 0x1b,
    REPORT_PRINTF = 0x82,
    REPORT_HDL = 0xfe,
};

enum command {
    CMD_NONE = 0x00,
    CMD_CONTINUE_WRITE = 0x01,
    CMD_IDENTIFY = 0x02,
    CMD_RESET = 0x04,
    CMD_ENABLE_REPORT = 0x05,
    CMD_DISABLE_REPORT = 0x06,
    CMD_GET_BOOT_INFO = 0x10,
    CMD_ERASE_FLASH = 0x11,
    CMD_WRITE_FLASH = 0x12,
    CMD_READ_FLASH = 0x13,
    CMD_RUN_APPLICATION_FIRMWARE = 0x14,
    CMD_SPI_MASTER_WRITE_THEN_READ = 0x15,
    CMD_REBOOT_TO_ROM_BOOTLOADER = 0x16,
    CMD_RUN_BOOTLOADER_FIRMWARE = 0x1f,
    CMD_GET_APPLICATION_INFO = 0x20,
    CMD_GET_STATIC_CONFIG = 0x21,
    CMD_SET_STATIC_CONFIG = 0x22,
    CMD_GET_DYNAMIC_CONFIG = 0x23,
    CMD_SET_DYNAMIC_CONFIG = 0x24,
    CMD_GET_TOUCH_REPORT_CONFIG = 0x25,
    CMD_SET_TOUCH_REPORT_CONFIG = 0x26,
    CMD_REZERO = 0x27,
    CMD_COMMIT_CONFIG = 0x28,
    CMD_DESCRIBE_DYNAMIC_CONFIG = 0x29,
    CMD_PRODUCTION_TEST = 0x2a,
    CMD_SET_CONFIG_ID = 0x2b,
    CMD_ENTER_DEEP_SLEEP = 0x2c,
    CMD_EXIT_DEEP_SLEEP = 0x2d,
    CMD_GET_TOUCH_INFO = 0x2e,
    CMD_GET_DATA_LOCATION = 0x2f,
    CMD_DOWNLOAD_CONFIG = 0x30,
};

enum touch_report_code {
    TOUCH_END = 0,
    TOUCH_FOREACH_ACTIVE_OBJECT,
    TOUCH_FOREACH_OBJECT,
    TOUCH_FOREACH_END,
    TOUCH_PAD_TO_NEXT_BYTE,
    TOUCH_TIMESTAMP,
    TOUCH_OBJECT_N_INDEX,
    TOUCH_OBJECT_N_CLASSIFICATION,
    TOUCH_OBJECT_N_X_POSITION,
    TOUCH_OBJECT_N_Y_POSITION,
    TOUCH_OBJECT_N_Z,
    TOUCH_OBJECT_N_X_WIDTH,
    TOUCH_OBJECT_N_Y_WIDTH,
    TOUCH_OBJECT_N_TX_POSITION_TIXELS,
    TOUCH_OBJECT_N_RX_POSITION_TIXELS,
    TOUCH_0D_BUTTONS_STATE,
    TOUCH_GESTURE_DOUBLE_TAP,
    TOUCH_FRAME_RATE,
    TOUCH_POWER_IM,
    TOUCH_CID_IM,
    TOUCH_RAIL_IM,
    TOUCH_CID_VARIANCE_IM,
    TOUCH_NSM_FREQUENCY,
    TOUCH_NSM_STATE,
    TOUCH_NUM_OF_ACTIVE_OBJECTS,
    TOUCH_NUM_OF_CPU_CYCLES_USED_SINCE_LAST_FRAME,
    TOUCH_TUNING_GAUSSIAN_WIDTHS = 0x80,
    TOUCH_TUNING_SMALL_OBJECT_PARAMS,
    TOUCH_TUNING_0D_BUTTONS_VARIANCE,
    TOUCH_ROI_DATA = 0xCA,
    TOUCH_GRIP_DATA = 0xCB,
    TOUCH_ESD_DETECT = 0xCC,
};

static struct syna_tcm_hcd *tcm_hcd = NULL;
static unsigned char buffer[FIXED_READ_LENGTH] = {0};
struct mxt_tui_data __attribute__((weak)) tui_mxt_data;

static struct spi_config_chip tp_chip_info = {
    .hierarchy = SSP_MASTER,
    .slave_tx_disable = 1,
    .cs_control = NULL,
};

static struct spi_device spi_tp = {
    .max_speed_hz = 10000000, /* speed 10000000 bit */
    .mode = SPI_MODE_3,
    .bits_per_word = 8, /* 8 bit */
    .controller_data = &tp_chip_info,
};

void ts_spi_cs_set(u32 control);

static inline unsigned int ceil_div(unsigned int dividend, unsigned int divisor)
{
    if (divisor != 0)
        return (dividend + divisor - 1) / divisor;
    return 0;
}

static inline unsigned int le2_to_uint(const unsigned char *src)
{
    return (unsigned int)src[0] + (unsigned int)src[1] * 0x100;
}

static int syna_tcm_alloc_mem(struct syna_tcm_buffer *temp_buffer, unsigned int size)
{
    if (size > temp_buffer->buf_size) {
        if (!(temp_buffer->buf)) {
            SRE_MemFree(0, temp_buffer->buf);
            temp_buffer->buf = NULL;
        }
        temp_buffer->buf = SRE_MemAlloc(0, 0, size);
        if (!(temp_buffer->buf)) {
            TP_LOG_ERR("%s: Failed to allocate memory\n", __func__);
            TP_LOG_ERR("%s: Allocation size = %d\n", __func__, size);
            temp_buffer->buf_size = 0;
            temp_buffer->data_length = 0;
            return SYNA_ERR_STATUS;
        }
        temp_buffer->buf_size = size;
    }

    (void)memset_s(temp_buffer->buf, temp_buffer->buf_size, 0x00, temp_buffer->buf_size);
    temp_buffer->data_length = 0;

    return 0;
}

static void syna_tcm_free_mem(struct syna_tcm_buffer *temp_buffer)
{
    if (temp_buffer->buf) {
        SRE_MemFree(0, temp_buffer->buf);
        temp_buffer->buf = NULL;
        temp_buffer->buf_size = 0;
        temp_buffer->data_length = 0;
    }
}

static int syna_tcm_i3c_read_data(unsigned char *data,
    unsigned int length)
{
    int retval;

    retval = ts_tui_i3c_block_read(data, length, SYNA_I3C_ADDR, 4); /* 4:bus num */
    return retval;
}

static int syna_tcm_i3c_write_data(unsigned char *data,
    unsigned int length)
{
    int retval;

    retval = ts_tui_i3c_block_write(data, length, SYNA_I3C_ADDR, 4); /* 4:bus num */
    return retval;
}


/*
 * syna_tcm_i2c_read() - retrieve specific number of data bytes from device
 *
 * @tcm_hcd: handle of core module
 * @in_buf: buffer for storing data retrieved from device
 * @length: number of bytes to retrieve from device
 *
 * Read transactions are carried out until the specific number of data bytes are
 * retrieved from the device and stored in in_buf.
 */

int syna_tcm_i3c_read(unsigned char *in_buf, unsigned int length)
{
    int retval;
    TP_LOG_DEBUG("length:%d, tcm_hcd->rd_chunk_size = %d\n",length , tcm_hcd->rd_chunk_size);

    if (length > tcm_hcd->rd_chunk_size) {
        TP_LOG_ERR("length is too big\n");
        return -1;
    }

    retval = syna_tcm_alloc_mem(&tcm_hcd->temp, length);
    if (retval < 0) {
        TP_LOG_ERR("Failed to allocate memory for tcm_hcd->temp.buf\n");
        return retval;
    }

    retval = syna_tcm_i3c_read_data(tcm_hcd->temp.buf, length);
    if (retval < 0) {
        TP_LOG_ERR("Failed to read from device\n");
        return retval;
    }

    TP_LOG_DEBUG("temp buf:%x, %x, %x, %x, %x, %x\n", tcm_hcd->temp.buf[0], tcm_hcd->temp.buf[1], tcm_hcd->temp.buf[2],
        tcm_hcd->temp.buf[3], tcm_hcd->temp.buf[4], tcm_hcd->temp.buf[5]);

    retval = memcpy_s(&in_buf[0], length, &tcm_hcd->temp.buf[0], length);
    if (retval != 0)
        TP_LOG_ERR("in_buf memcpy failed\n");
    return 0;
}

static int syna_tcm_i3c_write(unsigned char *data,
    unsigned int length)
{
    int retval;

    retval = syna_tcm_i3c_write_data(data, length);
    if (retval < 0) {
        TP_LOG_ERR("Failed to read from device\n");
        return retval;
    }
    return retval;
}

int syna_tcm_spi_read(unsigned char *rxbuf, unsigned short size)
{
    u32 tp_spi_bus_addr = (u32)TP_SPI_BUS_ADDR;
    int ret;
    struct spi_transfer t = {
        .rx_buf = rxbuf,
        .len = size,
        .delay_usecs = 0,
        .cs_change = 0,
    };
    struct spi_message m = {
        .transfers = &t,
        .transfer_num = 1,
        .actual_length = 0,
        .status = 0,
    };

    ret = hisi_spi_init(tp_spi_bus_addr, &spi_tp);
    if (ret != 0)
        return SYNA_ERR_STATUS;

    ts_spi_cs_set(GPIOMUX_LOW);
    hisi_spi_polling_transfer(tp_spi_bus_addr, &m);
    ts_spi_cs_set(GPIOMUX_HIGH);
    hisi_spi_exit(tp_spi_bus_addr);
    if (m.status != 0)
        return SYNA_ERR_STATUS;

    return 0;
}

static int syna_tcm_read(unsigned char *rxbuf, unsigned short size)
{
    int ret;

    if (tui_mxt_data.tui_special_feature_support & TP_TUI_BUS_TYPE_MASK)
        ret = syna_tcm_i3c_read(rxbuf, size);
    else
        ret = syna_tcm_spi_read(rxbuf, size);
    return ret;
}
static int syna_tcm_spi_write(unsigned char *txbuf, unsigned short size)
{
    u32 tp_spi_bus_addr = (u32)TP_SPI_BUS_ADDR;
    int ret;
    struct spi_transfer t = {
        .tx_buf = txbuf,
        .len = size,
        .delay_usecs = 0,
        .cs_change = 0,
    };
    struct spi_message m = {
        .transfers = &t,
        .transfer_num = 1,
        .actual_length = 0,
        .status = 0,
    };

    ret = hisi_spi_init(tp_spi_bus_addr, &spi_tp);
    if (ret != 0)
        return SYNA_ERR_STATUS;

    ts_spi_cs_set(GPIOMUX_LOW);
    hisi_spi_polling_transfer(tp_spi_bus_addr, &m);
    ts_spi_cs_set(GPIOMUX_HIGH);
    hisi_spi_exit(tp_spi_bus_addr);
    if (m.status != 0)
        return SYNA_ERR_STATUS;
    return 0;
}

static int syna_tcm_write(unsigned char *txbuf, unsigned short size)
{
    int ret;

    if (tui_mxt_data.tui_special_feature_support & TP_TUI_BUS_TYPE_MASK)
        ret = syna_tcm_i3c_write(txbuf, size);
    else
        ret = syna_tcm_spi_write(txbuf, size);
    return ret;
}

static int touch_get_report_data(unsigned int offset, unsigned int bits, unsigned int *data)
{
    unsigned char mask;
    unsigned char byte_data;
    unsigned int output_data = 0;
    unsigned int bit_offset;
    unsigned int byte_offset;
    unsigned int data_bits;
    unsigned int available_bits;
    unsigned int remaining_bits;
    unsigned char *touch_report = NULL;

    if ((bits == 0) || (bits > BIT_PER_WORD)) {
        TP_LOG_ERR("Invalid number of bits\n");
        return -EINVAL;
    }
    if ((offset + bits) > (tcm_hcd->report.buffer.data_length * BIT_PER_BYTE)) {
        *data = 0;
        return 0;
    }

    touch_report = tcm_hcd->report.buffer.buf;
    remaining_bits = bits;
    bit_offset = offset % BIT_PER_BYTE;
    byte_offset = offset / BIT_PER_BYTE;

    while (remaining_bits) {
        byte_data = touch_report[byte_offset];
        byte_data >>= bit_offset;

        available_bits = BIT_PER_BYTE - bit_offset;
        data_bits = (available_bits < remaining_bits) ? available_bits : remaining_bits;
        mask = 0xff >> (BIT_PER_BYTE - data_bits);

        byte_data &= mask;
        output_data |= byte_data << (bits - remaining_bits);

        bit_offset = 0;
        byte_offset += 1;
        remaining_bits -= data_bits;
    }
    *data = output_data;
    return 0;
}

static int touch_parse_report(struct object_data *object_data)
{
    int retval;
    bool active_only = false;
    bool num_of_active_objects = false;
    unsigned char code;
    unsigned int size;
    unsigned int idx;
    unsigned int obj = 0;
    unsigned int next = 0;
    unsigned int data = 0;
    unsigned int bits;
    unsigned int offset;
    unsigned int objects;
    unsigned int active_objects = 0;
    unsigned int report_size;
    unsigned int config_size;
    unsigned char *config_data = NULL;
    static unsigned int end_of_foreach;
    unsigned char bits_m;
    unsigned char bits_l;

    if ((tcm_hcd == NULL) || (object_data == NULL))
        return SYNA_ERR_STATUS;

    config_data = tcm_hcd->config.buf;
    config_size = tcm_hcd->config.data_length;
    report_size = tcm_hcd->report.buffer.data_length;
    size = sizeof(struct object_data) * TOUCH_MAX_FINGER_NUM;
    (void)memset_s(object_data, size, 0x00, size);
    num_of_active_objects = false;

    idx = 0;
    offset = 0;
    objects = 0;
    while (idx < config_size) {
        code = config_data[idx++];
        switch (code) {
        case TOUCH_END:
            tcm_hcd->num_of_finger = obj + 1;
            goto exit;
        case TOUCH_FOREACH_ACTIVE_OBJECT:
            obj = 0;
            next = idx;
            active_only = true;
            break;
        case TOUCH_FOREACH_OBJECT:
            obj = 0;
            next = idx;
            active_only = false;
            break;
        case TOUCH_FOREACH_END:
            end_of_foreach = idx;
            if (active_only) {
                if (num_of_active_objects) {
                    objects++;
                    if (objects < active_objects)
                        idx = next;
                } else if (offset < (report_size * BIT_PER_BYTE)) {
                    idx = next;
                }
            } else {
                obj++;
                if (obj < TOUCH_MAX_FINGER_NUM)
                    idx = next;
            }
            break;
        case TOUCH_PAD_TO_NEXT_BYTE:
            offset = ceil_div(offset, BIT_PER_BYTE) * BIT_PER_BYTE;
            break;
        case TOUCH_OBJECT_N_INDEX:
            bits = config_data[idx++];
            retval = touch_get_report_data(offset, bits, &obj);
            if (retval < 0) {
                TP_LOG_ERR("Failed to get object index\n");
                return retval;
            }
            offset += bits;
            break;
        case TOUCH_OBJECT_N_CLASSIFICATION:
        case TOUCH_OBJECT_N_X_POSITION:
        case TOUCH_OBJECT_N_Y_POSITION:
        case TOUCH_OBJECT_N_Z:
            bits = config_data[idx++];
            retval = touch_get_report_data(offset, bits, &data);
            if (retval < 0) {
                TP_LOG_ERR("Failed to get object z\n");
                return retval;
            }
            if (code == TOUCH_OBJECT_N_CLASSIFICATION)
                object_data[obj].status = data;
            else if (code == TOUCH_OBJECT_N_X_POSITION)
                object_data[obj].x_pos = data;
            else if (code == TOUCH_OBJECT_N_Y_POSITION)
                object_data[obj].y_pos = data;
            else if (code == TOUCH_OBJECT_N_Z)
                object_data[obj].z = data;
            offset += bits;
            break;
        case TOUCH_NUM_OF_ACTIVE_OBJECTS:
            bits = config_data[idx++];
            retval = touch_get_report_data(offset, bits, &data);
            if (retval < 0) {
                TP_LOG_ERR("Failed to get number of active objects\n");
                return retval;
            }
            active_objects = data;
            num_of_active_objects = true;
            offset += bits;
            if (data == 0)
                idx = end_of_foreach;
            break;
        case TOUCH_ROI_DATA:
            bits_m = config_data[idx++];
            bits_l = config_data[idx++];
            bits = (bits_l << 8) | bits_m;
            offset += bits;
            break;
        default:
            bits = config_data[idx++];
            offset += bits;
            break;
        }
    }
exit:
    return 0;
}

int touch_report(struct ts_tui_fingers *report_data)
{
    int retval;
    unsigned int idx;
    unsigned int status;
    unsigned int touch_count;
    struct object_data *object_data = NULL;
    struct ts_tui_fingers *info = NULL;

    if (tcm_hcd == NULL) {
        TP_LOG_ERR("Invalid tcm_hcd\n");
        return SYNA_ERR_STATUS;
    }
    object_data = tcm_hcd->object_data;

    info = (struct ts_tui_fingers *)SRE_MemAlloc(0, 0, sizeof(*info));
    if (info == NULL) {
        TP_LOG_ERR("Failed to alloc mem for info!\n");
        return SYNA_ERR_STATUS;
    }

    retval = touch_parse_report(object_data);
    if (retval < 0) {
        TP_LOG_ERR("Failed to parse touch report\n");
        goto exit;
    }
    touch_count = 0;
    for (idx = 0; idx < tcm_hcd->num_of_finger; idx++) {
        if ((tcm_hcd->prev_status[idx] == LIFT) && (object_data[idx].status == LIFT))
            status = NOP;
        else
            status = object_data[idx].status;

        switch (status) {
        case LIFT:
            info->fingers[idx].x = 0;
            info->fingers[idx].y = 0;
            break;
        case FINGER:
        case GLOVED_FINGER:
            info->fingers[idx].x = object_data[idx].x_pos;
            info->fingers[idx].y = object_data[idx].y_pos;
            info->fingers[idx].pressure = object_data[idx].z;
            TP_LOG_DEBUG("Finger %d:, status: %d\n", idx, status);
            touch_count++;
            break;
        default:
            break;
        }
        tcm_hcd->prev_status[idx] = status;
    }
    info->cur_finger_number = touch_count;
    ts_tui_algo_t1(info, report_data);
exit:
    SRE_MemFree(0, info);
    return retval;
}

static int syna_get_package_header(struct syna_tcm_message_header **header)
{
    bool retry = true;
    int retval;
    static int error_log_count;

    do {
        (void)memset_s(buffer, sizeof(buffer), 0xFF, FIXED_READ_LENGTH);
        retval = syna_tcm_read(buffer, FIXED_READ_LENGTH);
        if (retval < 0) {
            TP_LOG_ERR("Failed to read from device\n");
            if (retry) {
                if (tui_mxt_data.tui_special_feature_support &
                    TP_TUI_BUS_TYPE_MASK)
                    SRE_DelayMs(READ_RETRY_MS);
                else
                    SRE_DelayUs(READ_RETRY_US);
                retry = false;
                continue;
            }
            return retval;
        }

        (*header) = (struct syna_tcm_message_header *)buffer;
        if ((*header)->marker != MESSAGE_MARKER) {
            if (error_log_count < MAX_RETRY_NUM) {
                error_log_count++;
                TP_LOG_ERR("Incorrect header marker (0x%x),error_log_count=%d\n", (*header)->marker, error_log_count);
            }
            retval = SYNA_ERR_STATUS;
            if (retry) {
                if (tui_mxt_data.tui_special_feature_support &
                    TP_TUI_BUS_TYPE_MASK)
                    SRE_DelayMs(READ_RETRY_MS);
                else
                    SRE_DelayUs(READ_RETRY_US);
                retry = false;
                continue;
            }
            return retval;
        }
        retry = false;
    } while (retry);

    return 0;
}

static int syna_tcm_read_one_package()
{
    int retval;
    struct syna_tcm_message_header *header = NULL;

    retval = syna_get_package_header(&header);
    if (retval < 0) {
        TP_LOG_INFO("get head error");
        return retval;
    }

    tcm_hcd->status_report_code = header->code;
    tcm_hcd->payload_length = le2_to_uint(header->length);

    TP_LOG_DEBUG("Header code = 0x%x\n", tcm_hcd->status_report_code);
    TP_LOG_DEBUG("Payload length = %d\n", tcm_hcd->payload_length);

    if ((tcm_hcd->status_report_code <= STATUS_ERROR) || (tcm_hcd->status_report_code == STATUS_INVALID)) {
        switch (tcm_hcd->status_report_code) {
        case STATUS_OK:
            break;
        case STATUS_CONTINUED_READ:
            /* print a info but continued to read */
            TP_LOG_ERR("Out-of-sync continued read\n");
            /* fall-through */
        case STATUS_IDLE:
        case STATUS_BUSY:
            (void)memset_s((buffer + MESSAGE_HEADER_SIZE), (sizeof(buffer) - MESSAGE_HEADER_SIZE), 0x00,
                (FIXED_READ_LENGTH - MESSAGE_HEADER_SIZE));
            tcm_hcd->payload_length = 0;
            retval = 0;
            goto exit;
        default:
            TP_LOG_ERR("Incorrect header code (0x%02x)\n", tcm_hcd->status_report_code);
            if (tcm_hcd->status_report_code == STATUS_INVALID)
                tcm_hcd->payload_length = 0;
        }
    }

    retval = 0;
exit:
    return retval;
}

static int syna_tcm_get_report_config(void)
{
    int retval;
    unsigned char tx_buf[READ_CFG_CMD_SIZE] = { CMD_GET_TOUCH_REPORT_CONFIG, 0, 0 };
    unsigned char *report_config = NULL;

    if (tcm_hcd == NULL)
        return SYNA_ERR_STATUS;

    SRE_DelayMs(10); /* delay 10 */
    report_config = (unsigned char *)SRE_MemAlloc(0, 0, TOUCH_REPORT_CONFIG_SIZE + MESSAGE_HEADER_SIZE);
    if (report_config == NULL) {
        TP_LOG_ERR("Alloc memory failed\n");
        return SYNA_ERR_STATUS;
    }
    (void)memset_s(report_config, TOUCH_REPORT_CONFIG_SIZE + MESSAGE_HEADER_SIZE, 0,
        TOUCH_REPORT_CONFIG_SIZE + MESSAGE_HEADER_SIZE);

    retval = syna_tcm_alloc_mem(&(tcm_hcd->config), TOUCH_REPORT_CONFIG_SIZE);
    if (retval) {
        TP_LOG_ERR("Alloc memory failed\n");
        goto err_exit;
    }

    retval = syna_tcm_write(tx_buf, READ_CFG_CMD_SIZE);
    if (retval)
        goto err_exit;

    if (tui_mxt_data.tui_special_feature_support & TP_TUI_BUS_TYPE_MASK)
        SRE_DelayMs(5); /* delay 5ms still ic ready */
    else
        SRE_DelayUs(1000); /* Delay 1000 =1ms, wait for IC response */
    retval = syna_tcm_read(report_config, TOUCH_REPORT_CONFIG_SIZE + MESSAGE_HEADER_SIZE);
    if (retval)
        goto err_exit;

    TP_LOG_DEBUG("report_config = 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n", report_config[0], report_config[OFFSET_BYTE1],
        report_config[OFFSET_BYTE2], report_config[OFFSET_BYTE3], report_config[OFFSET_BYTE4],
        report_config[OFFSET_BYTE5]);

    if ((report_config[0] != MESSAGE_MARKER) || (report_config[1] != STATUS_OK)) {
        retval = SYNA_ERR_STATUS;
        goto err_exit;
    }

    tcm_hcd->config.data_length = report_config[OFFSET_BYTE2] | (report_config[OFFSET_BYTE3] << OFFSET_BYTE8);
    retval = memcpy_s((unsigned char *)tcm_hcd->config.buf, TOUCH_REPORT_CONFIG_SIZE,
        &report_config[MESSAGE_HEADER_SIZE], TOUCH_REPORT_CONFIG_SIZE);
    if (retval)
        TP_LOG_ERR("memcpy_s failed\n");

err_exit:
    if (retval)
        syna_tcm_free_mem(&(tcm_hcd->config));
    SRE_MemFree(0, report_config);
    return retval;
}


int syna_tcm_get_data(struct ts_tui_fingers *report_data)
{
    int retval;
    unsigned int gpio;
    if (report_data == NULL)
        return SYNA_ERR_STATUS;

    if ((tui_mxt_data.tui_special_feature_support & TP_TUI_NEW_IRQ_MASK) == TP_TUI_NEW_IRQ_SUPPORT)
        gpio = tui_mxt_data.tui_irq_gpio;
    else
        gpio = TS_GPIO_IRQ;
    gpio_irq_disable(gpio);
    retval = syna_tcm_read_one_package();
    if (retval) {
        TP_LOG_ERR("syna_tcm_get_data, read touch data error\n");
        goto exit;
    }

    if (tcm_hcd->status_report_code >= REPORT_IDENTIFY) {
        tcm_hcd->report.buffer.buf = &buffer[MESSAGE_HEADER_SIZE];
        tcm_hcd->report.buffer.buf_size = tcm_hcd->payload_length;
        tcm_hcd->report.buffer.data_length = tcm_hcd->payload_length;
        tcm_hcd->report.id = tcm_hcd->status_report_code;
        retval = touch_report(report_data);
        if (retval) {
            TP_LOG_ERR("syna_tcm_get_data, get bad touch data\n");
            goto exit;
        }
    }

exit:
    gpio_irq_enable(gpio);
    return retval;
}

int syna_tcm_device_init(void)
{
    int retval;

    tcm_hcd = (struct syna_tcm_hcd *)SRE_MemAlloc(0, 0, sizeof(*tcm_hcd));
    if (tcm_hcd == NULL) {
        TP_LOG_ERR("Alloc tcm_hcd Failed\n");
        return SYNA_ERR_STATUS;
    }
    (void)memset_s(tcm_hcd, sizeof(struct syna_tcm_hcd), 0, sizeof(*tcm_hcd));
    tcm_hcd->rd_chunk_size = 512; /* 512:I3C chunk size */
    TP_LOG_INFO("tp_init tui_special_feature_support = 0x%x rd_chunk_size = %d\n",
        tui_mxt_data.tui_special_feature_support, tcm_hcd->rd_chunk_size);
    TP_LOG_INFO("tp_init tui_mxt_data.tui_irq_gpio = %d tui_irq_num = %d\n",
        tui_mxt_data.tui_irq_gpio, tui_mxt_data.tui_irq_num);
    retval = syna_tcm_get_report_config();
    if (retval) {
        TP_LOG_ERR("syna_tcm_device_init, get report config data error\n");
        goto exit;
    }
    return 0;
exit:
    SRE_MemFree(0, tcm_hcd);
    tcm_hcd = NULL;
    return retval;
}

void tui_syna_tcm_exit(void)
{
    if (tcm_hcd) {
        syna_tcm_free_mem(&(tcm_hcd->config));
        SRE_MemFree(0, tcm_hcd);
        tcm_hcd = NULL;
    }
}
