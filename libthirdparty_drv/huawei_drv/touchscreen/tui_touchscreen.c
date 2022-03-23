/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: TUI tp platform common driver
 * Author: chenpuwang
 * Create: 2020-09-21
 */

#include "tui_touchscreen.h"
#include "tui_touchscreen_panel.h"
#include "tui_touchscreen_platform.h"

struct tui_tp_data {
    char project_id[THP_PROJECT_ID_LEN + 1];
    uint8_t enable;
    uint16_t frame_data_addr;
    /* the size of thp_tui_data is 24 byte in tee os */
    uint8_t reserved[10];
};

static int32_t ts_type_index = -1;
struct tui_tp_data g_tp_tui_data;

struct tee_thp_frame_buff g_tee_tp_frame_buff;
static int32_t g_frame_count_all;
static int32_t g_frame_max_len = MAX_FRAME_LEN;

static struct ts_ops *ts_fn_list = NULL;
static enum sec_mode g_tp_mode;
static int32_t g_caller_pid;
static int32_t g_tp_report_status;

static int32_t ts_device_init(void);

/* platform interface */
struct tp_cfg {
    uint64_t tp_info_phy;
    int32_t type;
    enum sec_mode drv_mode;
    int32_t drv_pid;
    int32_t caller_pid;
};

struct tee_thp_frame_buff *get_tp_frame_buff(void)
{
    return &g_tee_tp_frame_buff;
}

bool init_tp_data(uint64_t tp_info_phy)
{
    uint64_t phy_addr = tp_info_phy;
    uint32_t phy_len = sizeof(g_tp_tui_data);
    uint32_t vm_addr;
    int32_t ret;
    int32_t rc;

    /* check tp_info_addr READ */
    tloge("%s:phy_addr = %u, phy_len = %u\n", __func__, phy_addr, phy_len);
    ret = check_secureos_addr(phy_addr, phy_len);
    if (ret != 0) {
        tloge("check sos addr error 0x%x\n", ret);
        return false;
    }

    ret = sre_mmap((paddr_t)phy_addr, phy_len, &vm_addr, non_secure, cache);
    if (ret != 0) {
        tloge("map from ns page failed 0x%x\n", ret);
        return false;
    }
    rc = memcpy_s(&g_tp_tui_data, phy_len, (const void *)(uintptr_t)vm_addr,
        phy_len);
    (void)sre_unmap(vm_addr, phy_len);
    if (rc != EOK) {
        tloge("copy error 0x%0x\n", rc);
        return false;
    }
    tloge("%s:project id = %s\n", __func__, g_tp_tui_data.project_id);
    return true;
}

void display_state_notify(bool mode)
{
    tloge("%s:mode = %u, g_tp_mode =%u\n", __func__, mode, g_tp_mode);
    g_tp_report_status = mode;
    if (mode) {
        tui_tp_set_frame_count(0);
        tui_tp_irq_conctrl(1);
    }
}

int32_t tui_tp_get_chip_type(void)
{
    int32_t type = -1;
    uint32_t index;
    uint32_t size;

    ts_type_index = 0;
    ts_fn_list = get_cur_ts_ops_data(&size);
    if ((ts_fn_list == NULL) || (size == 0)) {
        tloge("%s:ts_fn_list is null or size = 0\n", __func__);
        return type;
    }
    tlogd("%s:ts_fn_list size = %u\n", __func__, size);
    for (index = 0; index < size; index++) {
        if (!strncmp(ts_fn_list[index].device_name, (char *)&g_tp_tui_data,
            (uint32_t)strlen(ts_fn_list[index].device_name))) {
            ts_type_index = index;
            type = ts_fn_list[index].touch_device;
            break;
        }
    }
    tlogd("%s:type = %u, ts_type_index =%u\n", __func__, type, ts_type_index);
    return type;
}

int32_t tui_tp_init(int32_t type, void (*handler)(void *), void *data)
{
    int32_t result;
    uint32_t irq_num;
    uint32_t irqflags;

    if (handler == NULL) {
        tloge("%s:handler is null\n", __func__);
        return ERROR;
    }

    if (ts_type_index == -1) {
        tloge("%s:ts_type_index is invalid\n", __func__);
        return ERROR;
    }

    tui_tp_set_frame_count(0);
    result = tp_enter_secure_os_config();
    if (result < 0) {
        tloge("%s:failed\n", __func__);
        return ERROR;
    }
    g_tp_mode = SECURE_ENABLE;
    tloge("%s set to secure mode\n", __func__);
    result = ts_device_init();
    if (result) {
        tloge("%s fail\n", __func__);
        return ERROR;
    }
    irq_num = tui_tp_get_cur_irq_num();
    irqflags = tui_tp_get_cur_irq_flags(type);
    tloge("irq_num = %u, irqflags = %u\n", irq_num, irqflags);
    result = tui_tp_irq_request(irq_num, handler, irqflags, data);
    if (result) {
        tloge("%s:tp irq_num-%d irq request failed\n", __func__, irq_num);
        return ERROR;
    } else {
        tloge("%s:irq_num-%d irq request succeed\n", __func__, irq_num);
    }

    return 0;
}

#define THP_MAX_FRAME_NUM 5
void tui_tp_irq_thp_handler(const void *arg)
{
    int32_t frame_count;
    struct event_node node = {0};

    (VOID)arg;
    tloge("%s: enter, g_tp_mode =%u\n", __func__, g_tp_report_status);
    tui_tp_irq_conctrl(0);
    if (!g_tp_report_status) {
        tloge("%s:g_tp_report_status =  %d\n", __func__, g_tp_report_status);
        return;
    }
    frame_count = tui_tp_get_frame_count();
    tloge("%s: frame_count =%u\n", __func__, frame_count);
    if (frame_count < THP_MAX_FRAME_NUM) {
        tlogd("%s: ipc_msg_snd g_caller_pid = %x\n", __func__, g_caller_pid);
        (void)ipc_msg_snd(TUI_DRV_MSG_TP_EVENT, g_caller_pid, &node,
            sizeof(node));
        tui_tp_set_frame_count(tui_tp_get_frame_count() + 1);
    }
    return;
}

bool tui_tp_driver_init(void *cfg_data)
{
    int32_t rc;
    int32_t type;
    uint32_t s_ret;
    uint32_t *cur_pid = NULL;
    struct tp_cfg *cfg = (struct tp_cfg *)cfg_data;

    if (cfg == NULL)
        return false;
    g_caller_pid = cfg->caller_pid;
    rc = init_tp_data(cfg->tp_info_phy);
    if (!rc) {
        tloge("copy error 0x%0x\n", rc);
        return false;
    }
    tloge("%s:init_tp_data success, g_caller_pid = %u\n", __func__,
        g_caller_pid);
    type = tui_tp_get_chip_type();
    if (type < 0) {
        tloge("other tp device, not support\n");
        return false;
    }
    cur_pid = malloc(sizeof(*cur_pid));
    if (cur_pid == NULL) {
        tloge("alloc cur_pid failed\n");
        return false;
    }
    s_ret = SRE_TaskSelf(cur_pid);
    if (s_ret != SRE_OK) {
        tloge("get cur pid failed, ret=0x%x\n", s_ret);
        goto error;
    }
    tloge("%s:task pid=%u, type = %d\n", __func__, *cur_pid, type);
    if ((type >= THP_JDI_DEVICE_VICTORIA) && (type < MAX_THP_DEVICE_NUM)) {
        rc = tui_tp_init(type, (void *)tui_tp_irq_thp_handler, (void *)cur_pid);
    } else {
        tloge("unsupport ic type: %u\n", type);
        goto error;
    }

    tloge("%s out\n", __func__);
    free(cur_pid);
    return true;
error:
    free(cur_pid);
    return false;
}

int32_t tui_tp_exit(void)
{
    tloge("%s enter\n", __func__);
    ts_fn_list[ts_type_index].fn_touch_exit();
    tp_exit_secure_os_config();
    tui_tp_irq_conctrl(0);
    g_frame_count_all = 0;
    g_tp_mode = SECURE_DISABLE;
    g_caller_pid = 0;
    return 0;
}

int32_t ts_ioctl_get_frame(void *arg)
{
    int32_t ret;
    struct ts_frame_data *data = NULL;
    struct ts_info *arg_tmp = NULL;

    tlogd("%s:enter\n", __func__);
    arg_tmp = (struct ts_info *)arg;
    if (arg_tmp == NULL) {
        tloge("%s:arg_tmp == NULL\n", __func__);
        return ERROR;
    }

    irq_lock();
    data = &(arg_tmp->ts_ioctl_data.ts_frame_info);

    ret = ts_get_frame();
    if (ret) {
        irq_unlock();
        return ERROR;
    }

    ret = memcpy_s((void *)(data->buf), MAX_FRAME_LEN,
        (void *)&g_tee_tp_frame_buff.revbuff[0], MAX_FRAME_LEN - 1);
    if (ret != 0) {
        irq_unlock();
        return ERROR;
    }
    ret = memset_s((void *)&g_tee_tp_frame_buff, sizeof(g_tee_tp_frame_buff),
        0, sizeof(g_tee_tp_frame_buff));
    if (ret != 0) {
        irq_unlock();
        return ERROR;
    }
    irq_unlock();
    return NO_ERR;
}

static int32_t ts_ioctl_spi_sync(void *arg)
{
    int32_t ret;
    struct ts_reg_data *data = NULL;
    struct ts_info *arg_tmp = NULL;

    arg_tmp = (struct ts_info *)arg;
    if (arg_tmp == NULL) {
        tloge("%s:arg_tmp == NULL\n", __func__);
        return ERROR;
    }
    irq_lock();
    data = &(arg_tmp->ts_ioctl_data.reg_data);
    tlogd("%s: txbuf = %x, rxbuf =%x ,size = %d\n", __func__,
        data->txbuf, data->rxbuf, data->size);
    ret = ts_spi_sync((uint16_t)data->size, data->txbuf, data->rxbuf);
    tlogd("%s: rxbuf[0] = %x, rxbuf[1] =%x,  rxbuf[2] = %x,data->rxbuf[3] =%x\n",
        __func__, data->rxbuf[0], data->rxbuf[1], data->rxbuf[2], data->rxbuf[3]);
    irq_unlock();
    return ret;
}

static int32_t ts_ioctl_sync_frame(void *arg)
{
    (void)arg;
    if (g_frame_count_all)
        g_frame_count_all--;
    return NO_ERR;
}

static int32_t ts_ioctl_set_irq(void *arg)
{
    struct ts_info *arg_tmp;
    uint32_t enable = 0;
    uint32_t value;
    uint32_t gpio_num;

    arg_tmp = (struct ts_info *)arg;
    if (arg_tmp == NULL)
        return ERROR;

    if (arg_tmp->reserved == 1)
        enable = 1;

    tui_tp_irq_conctrl(enable);
    if (enable) {
        gpio_num = tui_tp_get_cur_gpio_num();
        value = tui_tp_get_gpio_value(gpio_num);
        if (value == 0)
            return ERROR;
    }
    return 0;
}

static int32_t ts_ioctl_get_project_id(void *arg)
{
    struct ts_info *arg_tmp = NULL;
    int32_t ret;
    char *data = NULL;

    arg_tmp = (struct ts_info *)arg;
    if (arg_tmp == NULL) {
        tloge("ts_info fail\n");
        return ERROR;
    }
    tloge("%s:enter\n", __func__);

    data = &(arg_tmp->ts_ioctl_data.project_id[0]);
    if (data != NULL) {
        ret = memcpy_s((void *)data, THP_PROJECT_ID_LEN,
            (const void *)ts_fn_list[ts_type_index].device_name,
            THP_PROJECT_ID_LEN);
        if (ret)
            tloge("project_id memcpy_s fail\n");
    }
    return 0;
}

int32_t ts_ioctl(uint32_t cmd, void *arg)
{
    int32_t ret;

    switch (cmd) {
    case TS_GET_FRAME:
        ret = ts_ioctl_get_frame(arg);
        tui_tp_irq_conctrl(1);
        break;
    case TS_SPI_SYNC:
        ret = ts_ioctl_spi_sync(arg);
        break;
    case TS_IRQ_CTL:
        ret = ts_ioctl_set_irq(arg);
        break;
    case TS_GET_PRO_ID:
        ret = ts_ioctl_get_project_id(arg);
        break;
    case TS_SYNC_FRAME:
        ret = ts_ioctl_sync_frame(arg);
        break;
    default:
        tloge("cmd unknown-%d.\n", cmd);
        ret = -EINVAL;
        break;
    }

    return ret;
}

/* platform functions */
static void ts_get_data(struct ts_tui_fingers *report_data)
{
    if (report_data == NULL)
        return;
    ts_fn_list[ts_type_index].fn_get_data(report_data);
}

static int32_t ts_device_init(void)
{
    tloge("%s enter\n", __func__);
    return ts_fn_list[ts_type_index].fn_touch_init();
}

int32_t ts_get_frame(void)
{
    struct ts_tui_fingers *report_data = NULL;

    return ts_fn_list[ts_type_index].fn_get_data(report_data);
}

int32_t hisi_tui_get_tpdata_read(struct ts_tui_finger *finger_data_buf,
    struct ts_tui_fingers *report_data)
{
    /*
     * Get interrupt status information from F01 Data1 register to
     * determine the source(s) that are flagging the interrupt.
     */
    if ((finger_data_buf == NULL) || (report_data == NULL))
        return ERROR;
    ts_get_data(report_data);

    finger_data_buf->status = report_data->fingers[0].status;
    finger_data_buf->x = report_data->fingers[0].x;
    finger_data_buf->y = report_data->fingers[0].y;
    return 0;
}

int32_t tui_tp_get_frame_count(void)
{
    return g_frame_count_all;
}

void tui_tp_set_frame_count(int32_t count)
{
    g_frame_count_all = count;
}

int32_t tui_tp_get_frame_max_len(void)
{
    return g_frame_max_len;
}

__attribute__((weak)) int32_t ts_spi_sync(uint16_t size, uint8_t *tx_buff, uint8_t *rx_buff)
{
    tloge("%s enter, %u, %x, %x\n", __func__, size, tx_buff, rx_buff);
    return 0;
}

__attribute__((weak)) void tui_tp_irq_conctrl(int32_t enable)
{
    tloge("%s enter, %d\n", __func__, enable);
    return;
}

__attribute__((weak)) uint32_t tui_tp_get_cur_gpio_num(void)
{
    return 0;
}

__attribute__((weak)) uint32_t tui_tp_get_gpio_value(uint32_t gpio_num)
{
    tloge("%s enter, %d\n", __func__, gpio_num);
    return 0;
}

__attribute__((weak)) struct ts_ops *get_cur_ts_ops_data(unsigned int *size)
{
    tloge("%s enter, %x\n", __func__, size);
    return NULL;
}

__attribute__((weak)) int32_t tp_enter_secure_os_config(void)
{
    return 0;
}

__attribute__((weak)) uint32_t tui_tp_get_cur_irq_num(void)
{
    return 0;
}

__attribute__((weak)) uint32_t tui_tp_get_cur_irq_flags(int32_t type)
{
    tloge("%s enter, %u\n", __func__, type);
    return 0;
}

__attribute__((weak)) int32_t tui_tp_irq_request(uint32_t gpio_id, void (*handler)(void *),
    uint32_t irqflags, void *data)
{
    tloge("%s enter, %u, %x, %x, %x\n", __func__, gpio_id, handler, irqflags, data);
    return 0;
}
