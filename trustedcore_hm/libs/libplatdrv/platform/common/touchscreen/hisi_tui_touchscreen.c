/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2020. All rights reserved.
 * Description: Implement of TUI core fwk
 * Author: lijie
 * Create: 2017-04-02
 */

#include <mem_ops.h>
#include <i2c.h>
#include <gpio.h>
#include <hisi_debug.h>
#include <hisi_boot.h>
#include "mem_page_ops.h"
#include "libhwsecurec/securec.h"
#include "sre_sys.h"
#include "sre_log.h"
#include "../../kirin/spi/spi.h"
#include "hisi_tui_touchscreen.h"
#include "tui_panel.h"
#ifdef CONFIG_HISI_MAILBOX
#include "ipc.h"
#endif
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
#include <i3c.h>
#endif
/* macro */
#define REG_SIZE 2
static unsigned int tui_tp_irq_gpio;
static int ts_type_index = -1;
struct tee_thp_frame_buff g_tee_tp_buff;
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3650)
static unsigned int fp_gpio_num;
#endif

int g_frame_count_all = 0;
int g_frame_max_len = MAX_FRAME_LEN;

#ifdef CONFIG_HISI_MAILBOX
#define THP_FINGER_DATA_LEN 24
static void (*g_thp_irq_handler)(void *) = NULL;
struct ts_tui_finger g_tui_finger_data = { 0 };
unsigned int g_thp_cur_pid = 0;
#endif

struct mxt_tui_data tui_mxt_data;
/* struct&func defines */
void ts_spi_cs_set(u32 control);

typedef int (*ptouch_device_init)(void);
typedef int (*ptouch_get_data)(struct ts_tui_fingers *report_data);

int parade_get_data(struct ts_tui_fingers *report_data);
int synaptics_get_data(struct ts_tui_fingers *report_data);
int syna_tcm_get_data(struct ts_tui_fingers *report_data);
int atmel_get_data(struct ts_tui_fingers *report_data);
int novatek_get_data(struct ts_tui_fingers *report_data);
int novatek_get_data_spi(struct ts_tui_fingers *report_data);
int st_get_data(struct ts_tui_fingers *report_data);
int st_get_data_new(struct ts_tui_fingers *report_data);
int ts_jdi_get_frame(struct ts_tui_fingers *report_data);
int sec_get_data(struct ts_tui_fingers *report_data);
int ts_novatek_get_frame(struct ts_tui_fingers *report_data);
int fts_get_data(struct ts_tui_fingers *report_data);
int fts_get_data_spi(struct ts_tui_fingers *report_data);
int gt1x_get_data(struct ts_tui_fingers *report_data);
int gtx8_get_data(struct ts_tui_fingers *report_data);
int brl_device_init(void);
int brl_get_data(struct ts_tui_fingers *report_data);
int ts_himax_get_frame(struct ts_tui_fingers *report_data);
int ts_himax_init(void);
int ts_ssl_get_frame(struct ts_tui_fingers *report_data);
int ts_ssl_init(void);
int ts_goodix_get_frame(struct ts_tui_fingers *report_data);
int ts_goodix_get_frame_gt9896(struct ts_tui_fingers *report_data);
int ts_goodix_get_frame_gt9897(struct ts_tui_fingers *report_data);
int ts_goodix_init(void);
int ts_novatek_init(void);
int ts_syn_get_frame(struct ts_tui_fingers *report_data);
int ts_syn_init(void);
int ts_st_init(void);
int ts_st_get_frame(struct ts_tui_fingers *report_data);
UINT32 SRE_SwMsleep(UINT32 uwMsecs);
void irq_lock();
void irq_unlock();


static struct spi_config_chip tp_chip_info = {
    .hierarchy = SSP_MASTER,
    .slave_tx_disable = 1,
    .cs_control = ts_spi_cs_set,
};

#define SPI_SPEED 10000000
#define SPI_BITS_RATE 8
static struct spi_device spi_tp = {
    .max_speed_hz = SPI_SPEED,
    .mode = SPI_MODE_0,
    .bits_per_word = SPI_BITS_RATE,
    .controller_data = &tp_chip_info,
};

struct ts_ops{
    char device_name[THP_PROJECT_ID_LEN + 1];
    enum touch_device_type touch_device;
    ptouch_device_init fn_touch_init;
    ptouch_get_data fn_get_data;
};

#ifdef CONFIG_HISI_MAILBOX
struct pkt_header_sensorhub_t {
    UINT8 tag;
    UINT8 cmd;
    UINT8 resp : 1; // 1:respond
    UINT8 rsv : 3;  // 3:reserved
    UINT8 core : 4; // 4:target core
    UINT8 partial_order;
    UINT16 tranid;
    UINT16 length;
};

struct pkt_thp_finger_data_req_t{
    struct pkt_header_sensorhub_t hd;
    char data[THP_FINGER_DATA_LEN];
};

static int ts_shb_init(void)
{
    HISI_PRINT_INFO("ts_shb_init\n");
    return 0;
}

static int ts_shb_get_data(struct ts_tui_fingers *report_data)
{
    if (report_data == NULL)
        return ERROR;

    report_data->fingers[0].x = g_tui_finger_data.x;
    report_data->fingers[0].y = g_tui_finger_data.y;
    report_data->fingers[0].status = g_tui_finger_data.status;
    report_data->cur_finger_number = 1; /* shb thp only support 1 */

    return 0;
}
#endif

static struct ts_ops ts_fn_list[] = {
    { IC_SYNATPICS, SYNATPICS_DEVICE, synaptics_device_init, synaptics_get_data, },
    { IC_SYNATPICS_TCM, SYNA_TCM_DEVICE, syna_tcm_device_init, syna_tcm_get_data, },
    { IC_ATMEL, ATMEL_DEVICE, atmel_device_init, atmel_get_data, },
    { IC_ST, ST_DEVICE, st_device_init, st_get_data, },
    { IC_SEC, SEC_DEVICE, sec_device_init, sec_get_data, },
    { IC_NOVATEK, NOVATEK_DEVICE, novatek_device_init, novatek_get_data, },
    { IC_NOVATEK_SPI, NOVATEK_DEVICE, novatek_device_init_spi, novatek_get_data_spi, },
    { IC_PARADE, PARADE_DEVICE, parade_device_init, parade_get_data, },
    { IC_FTS, FTS_DEVICE, fts_device_init, fts_get_data, },
    { IC_FTS_SPI, FTS_DEVICE, fts_device_init, fts_get_data_spi, },
    { IC_GT1X, GT1X_DEVICE, gt1x_device_init, gt1x_get_data, },
    { IC_GTX8, GTX8_DEVICE, gtx8_device_init, gtx8_get_data, },
    { IC_THP_JDI_ALPS, THP_JDI_DEVICE_ALPS, ts_jdi_init, ts_jdi_get_frame, },
    { IC_THP_SHARP_ALPS, THP_NOVA_DEVICE_ALPS, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_LG_ALPS, THP_NOVA_DEVICE_ALPS, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_SHARP_EMLY, THP_SYN_DEVICE_EMLY, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_JDI_EMLY, THP_SYN_DEVICE_EMLY, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_LGD_EMLY, THP_NOVA_DEVICE_EMLY, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_LGD_HMA, THP_NOVA_DEVICE_HMA, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_SHARP_HMA, THP_SYN_DEVICE_HMA, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_JDI_HMA, THP_SYN_DEVICE_HMA, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_BOE_HMA, THP_HIMAX_DEVICE_HMA, ts_himax_init, ts_himax_get_frame, },
    { IC_THP_SSL_VOG, THP_SSL_DEVICE_VOG, ts_ssl_init, ts_ssl_get_frame, },
    { IC_THP_ALPS_GTX_VOG, THP_GTX_DEVICE_VOG, ts_goodix_init, ts_goodix_get_frame, },
    { IC_THP_DW_GTX_VOG, THP_GTX_DEVICE_VOG, ts_goodix_init, ts_goodix_get_frame, },
    { IC_THP_RCG_GTX_ELLA, THP_GTX_DEVICE_ELA, ts_goodix_init, ts_goodix_get_frame, },
    { IC_THP_NOP_GTX_ELLA, THP_GTX_DEVICE_ELA, ts_goodix_init, ts_goodix_get_frame, },
    { IC_THP_SDC_GTX_ELLA, THP_GTX_DEVICE_ELA, ts_goodix_init, ts_goodix_get_frame, },
    { IC_THP_SDC_TRX_GTX_ELLA, THP_GTX_DEVICE_ELA, ts_goodix_init, ts_goodix_get_frame, },
    { IC_THP_VISI_GTX_ELLA, THP_GTX_DEVICE_ELA, ts_goodix_init, ts_goodix_get_frame_gt9896, },
    { IC_SEC_Y761, SEC_DEVICE_RAL, sec_device_init, sec_get_data, },
    { IC_THP_TM_HARY_TD4330, THP_SYN_DEVICE_HARY, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_TM_HARY_SYN, THP_SYN_DEVICE_HARY, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_BOE_HARY_SYN, THP_SYN_DEVICE_HARY, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_MUTTO_HARY_SYN, THP_SYN_DEVICE_HARY, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_BOE_HARY_NOV, THP_NOVA_DEVICE_HARY, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_TM_HARY_NOV, THP_NOVA_DEVICE_HARY, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_AUO_HARY_NOV, THP_NOVA_DEVICE_HARY, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_BOE_POT_TD4330, THP_SYN_DEVICE_POT, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_TM_POT_SYN, THP_SYN_DEVICE_POT, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_BOE_POT_SYN, THP_SYN_DEVICE_POT, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_MUTTO_POT_SYN, THP_SYN_DEVICE_POT, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_BOE_POT_NOV, THP_NOVA_DEVICE_POT, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_TM_POT_NOV, THP_NOVA_DEVICE_POT, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_AUO_POT_NOV, THP_NOVA_DEVICE_POT, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_TM_TD4330_YAL, THP_SYN_DEVICE_YAL, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_TM_TD4320_YAL, THP_SYN_DEVICE_YAL, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_TM_TD4320_YAL_N, THP_SYN_DEVICE_YAL, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_LG_TD4320_YAL, THP_SYN_DEVICE_YAL, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_LG_TD4320_YAL_N, THP_SYN_DEVICE_YAL, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_CTC_NOV_YAL, THP_NOVA_DEVICE_YAL, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_CTC_FOCAL_YAL, THP_FTS_DEVICE_YAL, fts_device_init, ts_fts_get_frame, },
    { IC_THP_TM_NOV_YAL, THP_NOVA_DEVICE_YAL, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_BOE_NOV_YAL, THP_NOVA_DEVICE_YAL, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_TM_TD4320_YAL_B, THP_SYN_DEVICE_YAL, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_TM_TD4320_YAL_NB, THP_SYN_DEVICE_YAL, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_LG_FOCAL_YAL, THP_FTS_DEVICE_YAL, fts_device_init, ts_fts_get_frame, },
    { IC_THP_LG_TD4320_YAL_B, THP_SYN_DEVICE_YAL, ts_syn_init, ts_syn_get_frame, },
    { IC_ELAN_SCM_OFILM, ELAN_DEVICE, elan_device_init, elan_get_data, },
    { IC_ELAN_SCM_TOPTOUCH, ELAN_DEVICE, elan_device_init, elan_get_data, },
    { IC_ST_NEW, ST_DEVICE_NEW, st_device_init_new, st_get_data_new, },
    /* SPN use the same ic as YAL, for unnecessary macro doesn't add new */
    { IC_THP_TM_TD4320_SPN, THP_SYN_DEVICE_YAL, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_TM_TD4320_SPN_B0, THP_SYN_DEVICE_YAL, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_CTC_NOV_SPN, THP_NOVA_DEVICE_YAL, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_BOE_NOV_SPN, THP_NOVA_DEVICE_YAL, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_TM_NOV_SPN, THP_NOVA_DEVICE_YAL, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_CTC_FOCAL_SPN, THP_FTS_DEVICE_YAL, fts_device_init, ts_fts_get_frame, },
    { IC_THP_SSG_GTX_SEA, THP_GTX_DEVICE_SEA, ts_goodix_init, ts_goodix_get_frame, },
    { IC_GTX8_6861, GTX8_DEVICE_VRD, gtx8_device_init, gtx8_get_data, },
    { IC_GTX8_BRL_9886, GTX8_BRL_DEVICE_TET, brl_device_init, brl_get_data, },
#ifdef CONFIG_HISI_MAILBOX
    { IC_THP_LGD_SYNA_LIO, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_LGD_SYNA_LIO_FN, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_LGD_GDIX_LIO, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_SDC_SYNA_LIO, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_SDC_GDIX_LIO, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_SDC_GDIX_TAS, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_SDC_GDIX_TAS_FM, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_SDC_GDIX_TAS_T, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_BOE_SYNA_DW_ELS, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_BOE_SYNA_APS_ELS, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_BOE_GDIX_DW_ELS, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_BOE_SYNA_APS2_ELS, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_BOE_SYNA_DW2_ELS, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_LGD_SYNA_FPCV2_ELS, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_LGD_GDIX_ELS, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_LGD_SYNA_FPCV3_ELS, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_SDC_SYNA_ELS, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_BOE_GDIX_APS_ELS, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_BOE_GDIX_DW_ANA, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_BOE_GDIX_APS_ANA, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_BOE_GDIX_TM1_ANA, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_BOE_GDIX_APS2_ANA, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_BOE_GDIX_APS3_ANA, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_SDC_GDIX_ELSP, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
    { IC_THP_SHB_TUI_COMMON_ID, THP_SHB_DEVICE, ts_shb_init, ts_shb_get_data, },
#endif
    { IC_THP_BOE_NOV_WLZ, THP_NOVA_DEVICE_WLZ, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_TM_NOV_WLZ, THP_NOVA_DEVICE_WLZ, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_AUO_NOV_WLZ, THP_NOVA_DEVICE_WLZ, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_TCL_NOV_WLZ, THP_NOVA_DEVICE_WLZ, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_TM_SYNA_WLZ, THP_SYNA_DEVICE_WLZ, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_TCL_SYNA_WLZ, THP_SYNA_DEVICE_WLZ, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_BOE_SYNA_WLZ, THP_SYNA_DEVICE_WLZ, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_BOE_NOV_OXF, THP_NOVA_DEVICE_OXF, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_TM_NOV_OXF, THP_NOVA_DEVICE_OXF, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_AUO_NOV_OXF, THP_NOVA_DEVICE_OXF, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_TCL_NOV_OXF, THP_NOVA_DEVICE_OXF, ts_novatek_init, ts_novatek_get_frame, },
    { IC_THP_TM_SYNA_OXF, THP_SYNA_DEVICE_OXF, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_TCL_SYNA_OXF, THP_SYNA_DEVICE_OXF, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_BOE_SYNA_OXF, THP_SYNA_DEVICE_OXF, ts_syn_init, ts_syn_get_frame, },
    { IC_THP_BOE_GDIX_EDIN, THP_GTX_DEVICE_EDIN, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_BOE_GDIX_EDIN_ALPS, THP_GTX_DEVICE_EDIN, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_BOE_GDIX_EDIN_OFILM, THP_GTX_DEVICE_EDIN, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_BOE_GDIX_EDIN_DW, THP_GTX_DEVICE_EDIN, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_BOE_GDIX_EDIN_ALPS_HZ, THP_GTX_DEVICE_EDIN, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_BOE_GDIX_EDIN_DW_ES, THP_GTX_DEVICE_EDIN, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_BOE_GDIX_EDIN_ALPS_ES, THP_GTX_DEVICE_EDIN, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_VISI_GDIX_EDIN_DW, THP_GTX_DEVICE_EDIN, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_VISI_GDIX_EDIN_OFILM, THP_GTX_DEVICE_EDIN, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_VISI_GDIX_EDIN_ONCELL, THP_GTX_DEVICE_EDIN, ts_goodix_init,
       ts_goodix_get_frame_gt9896, },
    { IC_THP_VISIONOX_SYNA_EDIN, THP_SYN_DEVICE_EDIN, ts_syn_init,
       ts_syn_get_frame, },
    { IC_THP_VISI_SYNA_EDIN_OFILM, THP_SYN_DEVICE_EDIN, ts_syn_init,
       ts_syn_get_frame, },
    { IC_THP_VISI_SYNA_EDIN_ONCELL, THP_SYN_DEVICE_EDIN, ts_syn_init,
       ts_syn_get_frame, },
    { IC_THP_VISI_SYNA_EDIN_DW, THP_SYN_DEVICE_EDIN, ts_syn_init,
       ts_syn_get_frame, },
    { IC_THP_VISI_SYNA_EDIN_OFILM_HZ, THP_SYN_DEVICE_EDIN, ts_syn_init,
       ts_syn_get_frame, },
    { IC_THP_SSG_GDIX_BMH, THP_GTX_DEVICE_BMH, ts_goodix_init,
       ts_goodix_get_frame_gt9896, },
    { IC_THP_EDO_GDIX_BMH, THP_GTX_DEVICE_BMH, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_BOE_GDIX_JER, THP_GTX_DEVICE_JER, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_BOE_GDIX_JER_DW, THP_GTX_DEVICE_JER, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_BOE_GDIX_JER_DW_ES, THP_GTX_DEVICE_JER, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_BOE_GDIX_JER_ALPS, THP_GTX_DEVICE_JER, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_BOE_GDIX_JER_ALPS_NOV, THP_GTX_DEVICE_JER, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_BOE_GDIX_JER_ALPS_ES, THP_GTX_DEVICE_JER, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_BOE_GDIX_JER_OFILM, THP_GTX_DEVICE_JER, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_BOE_GDIX_JER_OFILM_NOV, THP_GTX_DEVICE_JER, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_VISI_GDIX_JER_DW, THP_GTX_DEVICE_JER, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_VISI_GDIX_JER_OFILM, THP_GTX_DEVICE_JER, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_VISI_GDIX_JER_ONCELL, THP_GTX_DEVICE_JER, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_VISI_SYNA_JER_OFILM, THP_SYNA_DEVICE_JER, ts_syn_init,
        ts_syn_get_frame, },
    { IC_THP_VISI_SYNA_JER_ONCELL, THP_SYNA_DEVICE_JER, ts_syn_init,
        ts_syn_get_frame, },
    { IC_THP_VISI_SYNA_JER_ONCELL_60HZ, THP_SYNA_DEVICE_JER, ts_syn_init,
        ts_syn_get_frame, },
    { IC_THP_VISL_SYNA_JER, THP_SYNA_DEVICE_JER, ts_syn_init,
        ts_syn_get_frame, },
    { IC_THP_SSG_GDIX_JEF, THP_GTX_DEVICE_JEF, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_EDO_GDIX_JEF, THP_GTX_DEVICE_JEF, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_TM_NOV_CDY, THP_NOVA_DEVICE_CDY, ts_novatek_init,
        ts_novatek_get_frame, },
    { IC_THP_TCL_NOV_CDY, THP_NOVA_DEVICE_CDY, ts_novatek_init,
        ts_novatek_get_frame, },
    { IC_THP_BOE_NOV_CDY, THP_NOVA_DEVICE_CDY, ts_novatek_init,
        ts_novatek_get_frame, },
    { IC_THP_BOE_SYNA_CDY, THP_SYNA_DEVICE_CDY, ts_syn_init,
        ts_syn_get_frame, },
    { IC_THP_BOE_GDIX_EDIN_DW_90HZ, THP_GTX_DEVICE_EDIN, ts_goodix_init,
        ts_goodix_get_frame_gt9896, },
    { IC_THP_BOE_GDIX_EDIN_ALPS_HZ_90HZ, THP_GTX_DEVICE_EDIN,
        ts_goodix_init, ts_goodix_get_frame_gt9896, },
    { IC_THP_BOE_ST_TET, THP_ST_DEVICE_TET, ts_st_init, ts_st_get_frame, },
    { IC_THP_SDC_ST_TET, THP_ST_DEVICE_TET, ts_st_init, ts_st_get_frame, },
    { IC_THP_BOE_ST_YA2_TET, THP_ST_DEVICE_TET, ts_st_init, ts_st_get_frame, },
    { IC_THP_BOE_ST_NEWSENSOR_TET, THP_ST_DEVICE_TET, ts_st_init, ts_st_get_frame, },
    { IC_THP_BOE_ST_EMITAP_TET, THP_ST_DEVICE_TET, ts_st_init, ts_st_get_frame, },
    { IC_THP_BOE_ST_COF_TET, THP_ST_DEVICE_TET, ts_st_init, ts_st_get_frame, },
    { IC_THP_BOE_ST_SW_TET, THP_ST_DEVICE_TET, ts_st_init, ts_st_get_frame, },
    { IC_THP_BOE_ST_DDIC_TET, THP_ST_DEVICE_TET, ts_st_init, ts_st_get_frame, },
    { IC_THP_BOE_GTX8_DDIC_TET, THP_ST_DEVICE_TET, ts_st_init, ts_st_get_frame, },
    { IC_THP_BOE_SYNA_ANG_DW, THP_SYNA_DEVICE_ANG, ts_syn_init,
        ts_syn_get_frame, },
    { IC_THP_BOE_SYNA_ANG_APS, THP_SYNA_DEVICE_ANG, ts_syn_init,
        ts_syn_get_frame, },
    { IC_THP_VISI_SYNA_ANG_DW, THP_SYNA_DEVICE_ANG, ts_syn_init,
        ts_syn_get_frame, },
    { IC_THP_VISI_SYNA_ANG_OFILM, THP_SYNA_DEVICE_ANG, ts_syn_init,
        ts_syn_get_frame, },
    { IC_THP_BOE_SYNA_BRQ_DW, THP_SYNA_DEVICE_BRQ, ts_syn_init,
        ts_syn_get_frame, },
    { IC_THP_BOE_SYNA_BRQ_APS, THP_SYNA_DEVICE_BRQ, ts_syn_init,
        ts_syn_get_frame, },
    { IC_THP_VISI_SYNA_BRQ_DW, THP_SYNA_DEVICE_BRQ, ts_syn_init,
        ts_syn_get_frame, },
    { IC_THP_VISI_SYNA_BRQ_OFILM, THP_SYNA_DEVICE_BRQ, ts_syn_init,
        ts_syn_get_frame, },
    { IC_THP_BOE_GDIX_ANG, THP_GTX_DEVICE_ANG, ts_goodix_init,
        ts_goodix_get_frame_gt9897, },
    { IC_THP_VISI_GDIX_ANG, THP_GTX_DEVICE_ANG, ts_goodix_init,
        ts_goodix_get_frame_gt9897, },
    { IC_THP_VISI_GDIX_ANG_OFILM, THP_GTX_DEVICE_ANG, ts_goodix_init,
        ts_goodix_get_frame_gt9897, },
    { IC_THP_BOE_GDIX_BRQ, THP_GTX_DEVICE_BRQ, ts_goodix_init,
        ts_goodix_get_frame_gt9897, },
    { IC_THP_VISI_GDIX_BRQ, THP_GTX_DEVICE_BRQ, ts_goodix_init,
        ts_goodix_get_frame_gt9897, },
    { IC_THP_VISI_GDIX_BRQ_OFILM, THP_GTX_DEVICE_BRQ, ts_goodix_init,
        ts_goodix_get_frame_gt9897, },
    { IC_THP_VISI_SYNA_ANG_FPCV2, THP_SYNA_DEVICE_ANG, ts_syn_init,
        ts_syn_get_frame, },
    { IC_THP_TM_SYNA_BRQ, THP_SYNA_DEVICE_BRQ, ts_syn_init,
        ts_syn_get_frame, },
    { IC_THP_TM_SYNA_BRQ_DW, THP_SYNA_DEVICE_BRQ, ts_syn_init,
        ts_syn_get_frame, },
    { IC_THP_BOE_GDIX_ANG_DW, THP_GTX_DEVICE_ANG, ts_goodix_init,
        ts_goodix_get_frame_gt9897, },
    { IC_THP_VISI_GDIX_ANG_FPCV2, THP_GTX_DEVICE_ANG, ts_goodix_init,
        ts_goodix_get_frame_gt9897, },
    { IC_THP_BOE_GDIX_BRQ_APS, THP_GTX_DEVICE_BRQ, ts_goodix_init,
        ts_goodix_get_frame_gt9897, },
    { IC_THP_BOE_GDIX_BRQ_DW, THP_GTX_DEVICE_BRQ, ts_goodix_init,
        ts_goodix_get_frame_gt9897, },
    { IC_THP_BOE_GDIX_BRQ_APLS, THP_GTX_DEVICE_BRQ, ts_goodix_init,
        ts_goodix_get_frame_gt9897, },
    { IC_THP_VISI_GDIX_BRQ_DW, THP_GTX_DEVICE_BRQ, ts_goodix_init,
        ts_goodix_get_frame_gt9897, },
    { IC_THP_VISI_GDIX_BRQ_FPCV2, THP_GTX_DEVICE_BRQ, ts_goodix_init,
        ts_goodix_get_frame_gt9897, },
};

/* I2c */
int ts_tui_i2c_read(unsigned char *buf, unsigned short len, unsigned int slave_addr)
{
    buf[0] &= MASK_8BIT;
    return hisi_i2c_read(I2C_ADDR, buf, len, slave_addr);
}

int ts_tui_i3c_block_read(unsigned char *buf, unsigned short len, unsigned int slave_addr, u32 bus_num)
{
    int ret = 0;

    if (buf == NULL) {
        HISI_PRINT_ERROR("buf is NULL\n");
        return ERROR;
    }
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
    hisi_i3c_init(bus_num);
    ret = hisi_i3c_block_read(bus_num, slave_addr, buf, len, 1);
    hisi_i3c_exit(bus_num);
#else
    HISI_PRINT_ERROR("i3c not support len=%d slave_addr=%d bus_num=%d\n", len, slave_addr, bus_num);
#endif
    return ret;
}

int ts_tui_i3c_block_write(unsigned char *buf, unsigned short len, unsigned int slave_addr, u32 bus_num)
{
    int ret = 0;

    if (buf == NULL) {
        HISI_PRINT_ERROR("buf is NULL\n");
        return ERROR;
    }
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
    hisi_i3c_init(bus_num);
    ret = hisi_i3c_block_write(bus_num, slave_addr, buf, len, 1);
    hisi_i3c_exit(bus_num);
#else
    HISI_PRINT_ERROR("i3c not support len=%d slave_addr=%d bus_num=%d\n", len, slave_addr, bus_num);
#endif
    return ret;
}

int ts_tui_i2c_read_directly(unsigned char *buf, unsigned short len, unsigned int slave_addr)
{
    return hisi_i2c_read_directly(I2C_ADDR, buf, len, slave_addr);
}

int ts_tui_i2c_read_reg16(unsigned char *buf, unsigned short len, unsigned int slave_addr)
{
    buf[0] &= MASK_8BIT;
    buf[1] &= MASK_8BIT;
    return hisi_i2c_read_reg16(I2C_ADDR, buf, len, slave_addr);
}

int ts_tui_i2c_write(unsigned char *buf, unsigned short len, unsigned int slave_addr)
{
    return hisi_i2c_write(I2C_ADDR, buf, len, slave_addr);
}

/* I2C tp data algo */
int ts_tui_algo_t1(struct ts_tui_fingers *in_info, struct ts_tui_fingers *out_info)
{
    int index;
    int id;

    if ((in_info == NULL) || (out_info == NULL)) {
        HISI_PRINT_ERROR("in_info or out_info is NULL\n");
        return ERROR;
    }

    for (index = 0, id = 0; index < TS_TUI_MAX_FINGER; index++, id++) {
        if (in_info->cur_finger_number == 0) {
            out_info->fingers[0].status = TS_FINGER_RELEASE;
            if (id >= 1)
                out_info->fingers[id].status = 0;
        } else {
            if ((in_info->fingers[index].x != 0) || (in_info->fingers[index].y != 0)) {
                out_info->fingers[id].x = in_info->fingers[index].x;
                out_info->fingers[id].y = in_info->fingers[index].y;
                out_info->fingers[id].pressure = in_info->fingers[index].pressure;
                out_info->fingers[id].status = TS_FINGER_PRESS;
                out_info->cur_finger_number++;
            } else {
                out_info->fingers[id].status = 0;
            }
        }
    }
    return NO_ERR;
}

/* SPI */
void ts_spi_cs_set(u32 control)
{
    u32 gpio_tp_spi_cs = (u32)GPIO_TP_SPI_CS;

    gpio_set_mode(gpio_tp_spi_cs, (u32)GPIOMUX_M0); /* lint !e516 */
    gpio_set_direction_output(gpio_tp_spi_cs);
    if (control == (u32)GPIOMUX_HIGH) {
        gpio_set_value(gpio_tp_spi_cs, (u32)GPIOMUX_HIGH);
        SRE_SwMsleep(1);
    } else if (control == (u32)GPIOMUX_LOW) {
        gpio_set_value(gpio_tp_spi_cs, (u32)GPIOMUX_LOW);
        SRE_SwMsleep(2); /* gpio switch sleep 2ms */
    } else {
        HISI_PRINT_ERROR("[ts_spi_cs_set]invalid parameter\n");
    }
}

void ts_swap_2byte(unsigned char *buf, unsigned int size)
{
    unsigned int i;
    unsigned char temp;

    if (size % REG_SIZE == 1) {
        /* lint -save -e515 */
        HISI_PRINT_ERROR("error size is odd. size=[%u]\n", size);
        /* lint */
        return;
    }

    for (i = 0; i < size; i += REG_SIZE) {
        temp = *(buf + i);
        *(buf + i) = *(buf + i + 1);
        *(buf + i + 1) = temp;
    }
}

int ts_spi_sync(unsigned short size, unsigned char *txbuf, unsigned char *rxbuf)
{
    struct spi_transfer t = {
        .rx_buf = rxbuf,
        .tx_buf = txbuf,
        .len = size,
        .delay_usecs = 0,
        .cs_change = 1,
    }; /* lint !e785 */
    struct spi_message m = {
        .transfers = &t,
        .transfer_num = 1,
        .actual_length = 0,
        .status = 0,
    };
    u32 tp_spi_bus_addr = (u32)TP_SPI_BUS_ADDR;
    int ret;

    ret = hisi_spi_init(tp_spi_bus_addr, &spi_tp);
    if (ret != 0)
        return ERROR;
    ts_spi_cs_set(GPIOMUX_HIGH);
    hisi_spi_polling_transfer(tp_spi_bus_addr, &m);
    hisi_spi_exit(tp_spi_bus_addr);
    if (m.status != 0)
        return ERROR;
    return 0;
}

/*  thp-tui-syscall */
int ts_ioctl_get_frame(void *arg)
{
    int ret;
    struct ts_frame_data *data = NULL;
    struct ts_info *arg_tmp = NULL;

    arg_tmp = (struct ts_info *)arg;
    if (arg_tmp == NULL)
        return ERROR;

    irq_lock();
    data = &(arg_tmp->ts_ioctl_data.ts_frame_info);

    ret = spi_tui_mutex();
    if (ret) {
        irq_unlock();
        return ERROR;
    }

    ret = ts_get_frame();
    if (ret) {
        irq_unlock();
        return ERROR;
    }

    ret = memcpy_s((void *)(data->buf), MAX_FRAME_LEN, (void *)&g_tee_tp_buff.revbuff[0], MAX_FRAME_LEN - 1);
    if (ret != 0) {
        irq_unlock();
        return ERROR;
    }
    ret = memset_s((void *)&g_tee_tp_buff, sizeof(struct tee_thp_frame_buff), 0, sizeof(struct tee_thp_frame_buff));
    if (ret != 0) {
        irq_unlock();
        return ERROR;
    }
    irq_unlock();
    return NO_ERR;
}

static int ts_ioctl_spi_sync(void *arg)
{
    int ret;
    struct ts_reg_data *data = NULL;
    struct ts_info *arg_tmp = NULL;

    arg_tmp = (struct ts_info *)arg;
    if (arg_tmp == NULL)
        return ERROR;

    irq_lock();
    data = &(arg_tmp->ts_ioctl_data.reg_data);

    if (ts_fn_list[ts_type_index].touch_device == THP_FTS_DEVICE_YAL) {
        ret = fts_spi_sync_thp((unsigned short)data->size, data->txbuf, data->rxbuf);
    } else {
        ret = ts_spi_sync((unsigned short)data->size, data->txbuf, data->rxbuf);
    }
    irq_unlock();
    return ret;
}

static int ts_ioctl_sync_frame(void *arg)
{
    (void)arg;
    if (g_frame_count_all)
        g_frame_count_all--;

    return NO_ERR;
}

static int ts_ioctl_set_irq(void *arg)
{
    struct ts_info *arg_tmp;
    unsigned int irq_flag = 0;
    unsigned int value;

    arg_tmp = (struct ts_info *)arg;
    if (arg_tmp == NULL)
        return ERROR;

    if (arg_tmp->reserved == 1)
        irq_flag = 1;

    gpio_irq_ctrl(tui_tp_irq_gpio, irq_flag);

    if (irq_flag) {
        value = gpio_get_value(tui_tp_irq_gpio);
        if (!value)
            return ERROR;
    }
    return 0;
}

static int ts_ioctl_get_project_id(void *arg)
{
    struct ts_info *arg_tmp = NULL;
    int ret;
    char *data = NULL;

    arg_tmp = (struct ts_info *)arg;
    if (arg_tmp == NULL) {
        HISI_PRINT_ERROR("ts_info fail\n");
        return ERROR;
    }
    data = &(arg_tmp->ts_ioctl_data.project_id[0]);
    if (data != NULL) {
        ret = memcpy_s((void *)data, THP_PROJECT_ID_LEN, (const void *)ts_fn_list[ts_type_index].device_name,
            THP_PROJECT_ID_LEN);
        if (ret)
            HISI_PRINT_ERROR("project_id memcpy_s fail\n");
    }
    return 0;
}

int ts_ioctl(unsigned int cmd, void *arg)
{
    int ret;

    switch (cmd) {
        case TS_GET_FRAME:
        ret = ts_ioctl_get_frame(arg);
        if ((hisi_tui_get_chip_type() == THP_SSL_DEVICE_VOG) || (hisi_tui_get_chip_type() == THP_SYN_DEVICE_EDIN) ||
            (hisi_tui_get_chip_type() == THP_SYNA_DEVICE_JER) || (hisi_tui_get_chip_type() == THP_SYNA_DEVICE_ANG) ||
            (hisi_tui_get_chip_type() == THP_SYNA_DEVICE_BRQ))
            gpio_irq_ctrl((u32)TS_GPIO_IRQ, 1);
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
        /* lint -save -e515 */
        HISI_PRINT_ERROR("cmd unknown-%d.\n", cmd);
        /* lint */
        ret = -EINVAL;
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

static int ts_device_init()
{
    return (ts_fn_list[ts_type_index].fn_touch_init());
}

int ts_get_frame(void)
{
    struct ts_tui_fingers *report_data = NULL;

    return (ts_fn_list[ts_type_index].fn_get_data(report_data));
}

int hisi_tui_get_chip_type(void)
{
    int type = -1;
    unsigned int index;

    for (index = 0; index < (sizeof(ts_fn_list)) / (sizeof(struct ts_ops)); index++) {
        if (!strncmp(ts_fn_list[index].device_name, (char *)&tui_mxt_data,
            (unsigned int)strlen(ts_fn_list[index].device_name))) {
            ts_type_index = index;
            type = ts_fn_list[index].touch_device;
            break;
        }
    }

    switch (type) {
    case THP_JDI_DEVICE_VICTORIA:
        g_frame_max_len = MAX_FRAME_LEN_JDI_VICTORIA;
        break;
    case THP_JDI_DEVICE_ALPS:
        g_frame_max_len = MAX_FRAME_LEN_JDI_ALPS;
        break;
    case THP_NOVA_DEVICE_ALPS:
        g_frame_max_len = MAX_FRAME_LEN_SHRP_ALPS;
        break;
    case THP_SYN_DEVICE_EMLY:
        g_frame_max_len = MAX_FRAME_LEN_SYN_EMLY;
        spi_tp.mode = SPI_MODE_3;
        break;
    case THP_NOVA_DEVICE_EMLY:
        g_frame_max_len = MAX_FRAME_LEN_NOVA_EMLY;
        break;
    case THP_NOVA_DEVICE_HMA:
        g_frame_max_len = MAX_FRAME_LEN_NOVA_HMA;
        break;
    case THP_SYN_DEVICE_HMA:
        g_frame_max_len = MAX_FRAME_LEN_SYN_HMA;
        spi_tp.mode = SPI_MODE_3;
        break;
    case THP_HIMAX_DEVICE_HMA:
        g_frame_max_len = MAX_FRAME_LEN_HIMAX_HMA;
        break;
    case THP_SYN_DEVICE_HARY:
        g_frame_max_len = MAX_FRAME_LEN_SYN_HARY;
        spi_tp.mode = SPI_MODE_3;
        break;
    case THP_NOVA_DEVICE_HARY:
        g_frame_max_len = MAX_FRAME_LEN_NOVA_HARY;
        break;
    case THP_SYN_DEVICE_POT:
        g_frame_max_len = MAX_FRAME_LEN_SYN_POT;
        spi_tp.mode = SPI_MODE_3;
        break;
    case THP_NOVA_DEVICE_POT:
        g_frame_max_len = MAX_FRAME_LEN_NOVA_POT;
        break;
    case THP_SSL_DEVICE_VOG:
        g_frame_max_len = MAX_FRAME_LEN_SSL_VOG;
        spi_tp.mode = SPI_MODE_3;
        break;
    case THP_GTX_DEVICE_VOG:
        g_frame_max_len = MAX_FRAME_LEN_GOODIX;
        spi_tp.max_speed_hz = SPI_MAX_SPEED_GTX;
        break;
    case THP_GTX_DEVICE_ELA:
        g_frame_max_len = MAX_FRAME_LEN_GOODIX;
        spi_tp.max_speed_hz = SPI_MAX_SPEED_GTX;
        break;
    case THP_GTX_DEVICE_SEA:
        g_frame_max_len = MAX_FRAME_LEN_GOODIX;
        spi_tp.max_speed_hz = SPI_MAX_SPEED_GTX;
        break;
    case THP_NOVA_DEVICE_YAL:
        g_frame_max_len = MAX_FRAME_LEN_NOVA_YAL;
        break;
    case THP_SYN_DEVICE_YAL:
        g_frame_max_len = MAX_FRAME_LEN_SYN_YAL;
        spi_tp.mode = SPI_MODE_3;
        break;
    case THP_FTS_DEVICE_YAL:
        g_frame_max_len = MAX_FRAME_LEN_FOCAL_YAL;
        spi_tp.mode = SPI_MODE_1;
        break;
    case THP_NOVA_DEVICE_OXF:
        g_frame_max_len = MAX_FRAME_LEN_NOVA_OW;
        spi_tp.mode = SPI_MODE_0;
        break;
    case THP_SYNA_DEVICE_OXF:
        g_frame_max_len = MAX_FRAME_LEN_SYN_OW;
        spi_tp.mode = SPI_MODE_3;
        break;
    case THP_NOVA_DEVICE_WLZ:
        g_frame_max_len = MAX_FRAME_LEN_NOVA_OW;
        spi_tp.mode = SPI_MODE_0;
        break;
    case THP_SYNA_DEVICE_WLZ:
        g_frame_max_len = MAX_FRAME_LEN_SYN_OW;
        spi_tp.mode = SPI_MODE_3;
        break;
    case THP_GTX_DEVICE_EDIN:
        g_frame_max_len = MAX_FRAME_LEN_GOODIX_EDIN;
        spi_tp.max_speed_hz = SPI_MAX_SPEED_GTX;
        break;
    case THP_SYN_DEVICE_EDIN:
        g_frame_max_len = MAX_FRAME_LEN_SYN_EDIN;
        spi_tp.mode = SPI_MODE_0;
        break;
    case THP_GTX_DEVICE_BMH:
        g_frame_max_len = MAX_FRAME_LEN_GOODIX;
        spi_tp.max_speed_hz = SPI_MAX_SPEED_GTX;
        break;
    case THP_GTX_DEVICE_JER:
        g_frame_max_len = MAX_FRAME_LEN_GOODIX;
        spi_tp.max_speed_hz = SPI_MAX_SPEED_GTX;
        break;
    case THP_SYNA_DEVICE_JER:
        g_frame_max_len = MAX_FRAME_LEN_SYN_JER;
        spi_tp.mode = SPI_MODE_0;
        break;
    case THP_GTX_DEVICE_JEF:
        g_frame_max_len = MAX_FRAME_LEN_GOODIX;
        spi_tp.max_speed_hz = SPI_MAX_SPEED_GTX;
        break;
    case THP_NOVA_DEVICE_CDY:
        g_frame_max_len = MAX_FRAME_LEN_NOVA_CDY;
        spi_tp.mode = SPI_MODE_0;
        break;
    case THP_SYNA_DEVICE_CDY:
        g_frame_max_len = MAX_FRAME_LEN_SYN_CDY;
        spi_tp.mode = SPI_MODE_3;
        break;
    case THP_ST_DEVICE_TET:
        g_frame_max_len = MAX_FRAME_LEN_ST_TET;
        spi_tp.mode = SPI_MODE_0;
        break;
    case THP_SYNA_DEVICE_ANG:
        g_frame_max_len = MAX_FRAME_LEN_SYN_ANG;
        spi_tp.mode = SPI_MODE_0;
        break;
    case THP_SYNA_DEVICE_BRQ:
        g_frame_max_len = MAX_FRAME_LEN_SYN_BRQ;
        spi_tp.mode = SPI_MODE_0;
        break;
    case THP_GTX_DEVICE_BRQ:
        g_frame_max_len = MAX_FRAME_LEN_GOODIX_BRQ;
        spi_tp.mode = SPI_MODE_0;
    case THP_GTX_DEVICE_ANG:
        g_frame_max_len = MAX_FRAME_LEN_GOODIX_BRQ;
        spi_tp.mode = SPI_MODE_0;
    case SYNATPICS_DEVICE:
    case SYNA_TCM_DEVICE:
    case ST_DEVICE:
    case PARADE_DEVICE:
    case NOVATEK_DEVICE:
    case ATMEL_DEVICE:
    case SEC_DEVICE:
    case FTS_DEVICE:
    case GT1X_DEVICE:
    case GTX8_DEVICE:
    case SEC_DEVICE_RAL:
    case ELAN_DEVICE:
    case THP_SHB_DEVICE:
    default:
        break;
    }
    return type;
}

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3650)
#define IRQ_TYPE_FP 2 /* irq from fingerprint */

/* when TUI displaying, we will use spi(irq) to call normal world fingerprint gpio irq handler */
static void hisi_fp_irq(void)
{
    struct tp_notify_data_t tp_notify_data = { 0 };
    int irq_type = IRQ_TYPE_FP;

    if (!tp_notify_addr) {
        HISI_PRINT_ERROR("tp_notify_addr is NULL\n");
        return;
    }
    (void)memset_s(tp_notify_addr, 500, 0, 500); /* addr length 500  */
    tp_notify_data.irq_type = irq_type;
    (void)memcpy_s(tp_notify_addr, sizeof(tp_notify_data), (char *)(&tp_notify_data),
        sizeof(tp_notify_data));      /* 376bytes */
    *((int *)tp_notify_addr - 1) = 1; /* lint !e826 */
    gic_spi_notify();
}
#endif

#ifdef CONFIG_HISI_MAILBOX
static void ipc_shb_thp_receive_func(union ipc_data *msg)
{
    struct pkt_thp_finger_data_req_t *finger_data = NULL;
    struct ts_tui_finger_shb *finger_data_shb = NULL;

    if (msg == NULL)
        return;

    finger_data = (struct pkt_thp_finger_data_req_t *)msg;
    finger_data_shb = (struct ts_tui_finger_shb *)finger_data->data;
    g_tui_finger_data.status = finger_data_shb->status;
    g_tui_finger_data.x = finger_data_shb->x;
    g_tui_finger_data.y = finger_data_shb->y;

    g_thp_irq_handler((void *)&g_thp_cur_pid);
}

int hisi_tui_shb_tp_init(void (*handler)(void *), UINT32 *cur_pid)
{
    int ret;

    if ((handler == NULL) || (cur_pid == NULL))
        return ERROR;

    g_thp_irq_handler = handler;
    g_thp_cur_pid = *cur_pid;
    ret = ipc_recv_notifier_register(AO_S_IPC, AO_MBX6_TO_ACPU, TAG_THP, ipc_shb_thp_receive_func);
    if (ret)
        HISI_PRINT_ERROR("tui shb thp ipc register failed");

    return ret;
}
#endif

static unsigned int ts_tui_check_irq_type_edge_falling(int type)
{
    return ((type == PARADE_DEVICE) || (type == NOVATEK_DEVICE) || (type == THP_JDI_DEVICE_ALPS) ||
        (type == THP_NOVA_DEVICE_ALPS) || (type == THP_SYN_DEVICE_EMLY) || (type == FTS_DEVICE) ||
        (type == GT1X_DEVICE) || (type == GTX8_DEVICE) || (type == THP_NOVA_DEVICE_EMLY) ||
        (type == THP_NOVA_DEVICE_HMA) || (type == THP_SYN_DEVICE_HMA) || (type == THP_HIMAX_DEVICE_HMA) ||
        (type == THP_SYN_DEVICE_HARY) || (type == THP_NOVA_DEVICE_HARY) || (type == THP_SYN_DEVICE_POT) ||
        (type == THP_NOVA_DEVICE_POT) || (type == THP_GTX_DEVICE_ELA) || (type == THP_GTX_DEVICE_VOG) ||
        (type == THP_SYN_DEVICE_YAL) || (type == THP_NOVA_DEVICE_YAL) || (type == THP_FTS_DEVICE_YAL) ||
        (type == THP_GTX_DEVICE_SEA) || (type == GTX8_DEVICE_VRD) || (type == THP_NOVA_DEVICE_OXF) ||
        (type == THP_SYNA_DEVICE_OXF) || (type == THP_NOVA_DEVICE_WLZ) || (type == THP_SYNA_DEVICE_WLZ) ||
        (type == THP_GTX_DEVICE_EDIN) || (type == THP_GTX_DEVICE_BMH) || (type == THP_GTX_DEVICE_JER) ||
        (type == THP_GTX_DEVICE_JEF) || (type == THP_NOVA_DEVICE_CDY) || (type == THP_SYNA_DEVICE_CDY) ||
        (type == THP_ST_DEVICE_TET) || (type == GTX8_BRL_DEVICE_TET) || (type == THP_GTX_DEVICE_BRQ) ||
        (type == THP_GTX_DEVICE_ANG));
}

static unsigned int ts_tui_set_irq_flag(int type)
{
    unsigned int irqflags = IRQ_TYPE_LEVEL_LOW;

    if (ts_tui_check_irq_type_edge_falling(type))
        irqflags = IRQ_TYPE_EDGE_FALLING;
    else if ((type == SYNA_TCM_DEVICE) || (type == THP_SSL_DEVICE_VOG) || (type == ELAN_DEVICE) ||
        (type == THP_SYN_DEVICE_EDIN) || (type == THP_SYNA_DEVICE_JER) || (type == THP_SYNA_DEVICE_ANG) ||
        (type == THP_SYNA_DEVICE_BRQ))
        irqflags = IRQ_TYPE_LEVEL_LOW;
    return irqflags;
}

int hisi_tui_tp_init(int type, void (*handler)(void *), void *data)
{
    unsigned gpio;
    int result;
    unsigned int irqflags;

    if (handler == NULL)
        return ERROR;

    if (ts_type_index == -1)
        return ERROR;
    if ((tui_mxt_data.tui_special_feature_support & TP_TUI_NEW_IRQ_MASK) == TP_TUI_NEW_IRQ_SUPPORT)
        tui_tp_irq_gpio = tui_mxt_data.tui_irq_gpio;
    else
        tui_tp_irq_gpio = TS_GPIO_IRQ;
    gpio = tui_tp_irq_gpio;
    result = ts_device_init();
    if (result) {
        HISI_PRINT_ERROR("hisi_tui_tp_init fail\n");
        return ERROR;
    }

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3650)
    result = get_fingerprint_gpio_num((int *)&fp_gpio_num);
    if (result != 0) {
        HISI_PRINT_ERROR("---failed to get fingerprint gpio num, result is %d\n", result);
        return ERROR;
    }
#endif
/* lint -e553 */
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680)
    gpio_set_mode(TS_GPIO_NUM, 4); /* gpio func 4  */
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO)
    /* set irq gpio mode to secure mode: function5 -> GPIO_012_SE */
    gpio_set_mode(TS_GPIO_NUM, 5); /* gpio func 5  */
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990)
    /* set irq gpio mode to secure mode: function3 -> GPIO_008_SE */
    if ((tui_mxt_data.tui_special_feature_support & TP_TUI_NEW_IRQ_MASK) != TP_TUI_NEW_IRQ_SUPPORT)
        gpio_set_mode(TS_GPIO_NUM, 3); /* gpio func 3  */

#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
    if ((tui_mxt_data.tui_special_feature_support & TP_TUI_NEW_IRQ_MASK) == TP_TUI_NEW_IRQ_SUPPORT) {
        gpio_set_mode(tui_mxt_data.tui_irq_num, 3); /* set irq gpio mode to secure mode: function3 -> GPIO_008_SE */
        HISI_PRINT_ERROR("tui_tp_init gpio_set_mode num = %u\n", tui_mxt_data.tui_irq_num);
    } else {
        HISI_PRINT_ERROR("tui_tp_init main screen gpio_set_mode\n");
        gpio_set_mode(TS_GPIO_NUM, 4); /* set irq gpio mode to secure mode: function4 -> GPIO_009_SE */
    }
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
    /* set irq gpio mode to secure mode: function4 -> GPIO_011_SE */
    gpio_set_mode(TS_GPIO_NUM, 4);
#endif
    irqflags = ts_tui_set_irq_flag(type);
    result = gpio_irq_request(gpio, handler, irqflags, data);
    if (result) {
        HISI_PRINT_ERROR("tp_init gpio-%d irq request failed\n", gpio);
        return ERROR;
    } else {
        HISI_PRINT_INFO("tp_init gpio-%d irq request succeed\n", gpio);
        /* disable irq for spi process wait hal to ctrl */
        if ((type >= THP_JDI_DEVICE_VICTORIA) && (type < MAX_THP_DEVICE_NUM))
            gpio_irq_ctrl(gpio, 0);
    }
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3650)
    /*
     * If fp gpio is in the same group with tp gpio
     * We should set fingerprint irq when tui is displaying.
     */
    /* group number 8 */
    if ((fp_gpio_num / 8) == (gpio / 8)) {
        HISI_PRINT_INFO("--- fp gpio %d and gpio %d is in the same gpio group\n", fp_gpio_num, gpio);
        /*
         * When TUI displaying, fp irq should be register.
         * If not register fp irq, fingerprint sensor can not send irq to fp driver in normal world.
         * because fp gpio and tp gpio is in one group(share one IRQ NUM)
         */
        gpio_set_direction_input(fp_gpio_num);
        result = gpio_irq_request(fp_gpio_num, hisi_fp_irq, IRQ_TYPE_EDGE_RISING, NULL);
        if (result) {
            HISI_PRINT_ERROR("--- fp gpio-%d irq request failed\n", fp_gpio_num);
            return ERROR;
        } else {
            HISI_PRINT_INFO("--- fp gpio-%d irq request succeed\n", fp_gpio_num);
        }
        /* when tui init there may be fp fiq, this will make sure that fp willbe responsed */
        /* This fix the low probability fp not response */
        unsigned int fp_rst_gpio_value;
        fp_rst_gpio_value = gpio_get_value(fp_gpio_num);
        if (fp_rst_gpio_value) {
            HISI_PRINT_INFO("--- get fp rst gpio value high\n");
            hisi_fp_irq();
        }
    }
#endif
    return 0;
}

int hisi_tui_tp_exit(void)
{
    unsigned gpio;
#ifdef CONFIG_HISI_MAILBOX
    int ret;
    int type = hisi_tui_get_chip_type();

    if (type == THP_SHB_DEVICE) {
        ret = ipc_recv_notifier_unregister(AO_S_IPC, AO_MBX6_TO_ACPU, TAG_THP);
        if (ret)
            HISI_PRINT_ERROR("tui shb thp ipc unregister failed");
        return ret;
    }
#endif
    gpio = tui_tp_irq_gpio;
    HISI_PRINT_INFO("hisi_tui_tp_exit:tp gpio-%d\n", gpio);
    gpio_free_irq(gpio);
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3660 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670 ||   \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680 ||    \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || \
    TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
    gpio_set_mode(TS_GPIO_NUM, 0);
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
    if ((tui_mxt_data.tui_special_feature_support & TP_TUI_NEW_IRQ_MASK) == TP_TUI_NEW_IRQ_SUPPORT) {
        gpio_set_mode(tui_mxt_data.tui_irq_num, 0); /* set irq gpio mode to normal mode: function0 */
        HISI_PRINT_ERROR("tui_tp_exit gpio_set_mode num = %u\n", tui_mxt_data.tui_irq_num);
    } else {
        gpio_set_mode(TS_GPIO_NUM, 0);
    }
#endif
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3650)
    /* group number 8 */
    if ((fp_gpio_num / 8) == (gpio / 8)) {
        gpio_free_irq(fp_gpio_num);
        if (gpio_get_value(fp_gpio_num)) {
            HISI_PRINT_INFO("--- get fp rst gpio value high\n");
            hisi_fp_irq();
        }
    }
#endif
    tui_syna_tcm_exit();
    tui_synaptics_exit();
    tui_atmel_exit();
    tui_st_exit();
    tui_st_exit_new();
    g_frame_count_all = 0;
    return 0;
}

int hisi_tui_get_tpdata_read(struct ts_tui_finger *finger_data_buf, struct ts_tui_fingers *report_data)
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
int hisi_tui_get_frame_count(void)
{
    return g_frame_count_all;
}
void hisi_tui_set_frame_count(int count)
{
    g_frame_count_all = count;
}
int hisi_tui_get_frame_max_len(void)
{
    return g_frame_max_len;
}

bool hisi_tui_set_mxt_data(struct mxt_tui_data *data)
{
    if (data == NULL)
        return false;

    if (memcpy_s(&tui_mxt_data, sizeof(tui_mxt_data), data, sizeof(*data)) != EOK)
        return false;

    return true;
}

void hisi_tui_thp_irq_ack(void)
{
    if (hisi_tui_get_chip_type() == THP_SSL_DEVICE_VOG ||
        (hisi_tui_get_chip_type() == THP_SYN_DEVICE_EDIN) ||
        (hisi_tui_get_chip_type() == THP_SYNA_DEVICE_JER) ||
        (hisi_tui_get_chip_type() == THP_SYNA_DEVICE_ANG) ||
        (hisi_tui_get_chip_type() == THP_SYNA_DEVICE_BRQ))
        gpio_irq_ctrl((u32)TS_GPIO_IRQ, 0);
}
