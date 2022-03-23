#include <phEseStatus.h>
#include <phNxpEse_Api_hisi_p61.h>
#include <phNxpEse_Internal_p61.h>
#include "p61.h"
#include "tee_log.h"

enum gpiomux_output_value {
    GPIOMUX_LOW = 0,
    GPIOMUX_HIGH,
};
#define OSU_PROP_CLA 0x80
#define OSU_PROP_INS 0xDF
#define OSU_PROP_RST_P1 0xEF

static bool mIsEseInitialized = false;

int p61_p61_factory_test(void)
{
    unsigned char test_cmd[] = {0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00};
    unsigned char response[256] = {0};
    unsigned char response_suc[] = {0x6F, 0x78, 0x84, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, 0xA5, 0x6C, 0x73, 0x66, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01, 0x60, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x02, 0x02, 0x03, 0x63, 0x09, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x03, 0x64, 0x16, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x02, 0x55, 0x64, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x03, 0x10, 0x64, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x03, 0x70, 0x65, 0x0E, 0x06, 0x0C, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x05, 0x07, 0x02, 0x00, 0x00, 0x01, 0x66, 0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x2A, 0x02, 0x6E, 0x01, 0x03, 0x9F, 0x65, 0x01, 0xFF, 0x90, 0x00};
    unsigned int response_len = 0;
    int ret = 0;
    unsigned int i;
    tloge("%s: eSE factory test begin ~~~~~~~~\n", __func__);

    p61_scard_connect(1, NULL, NULL);
    ret = p61_scard_transmit(1, test_cmd, sizeof(test_cmd), response, &response_len);
    p61_scard_disconnect(1);
    if (ret) {
        tloge("%s: eSE factory test fail because of transmit fail\n", __func__);
        return -1;
    }
    // compare
    for (i = 0; i < response_len; i++) {
        tloge("%s: i = %d, response[%d] = 0x%x\n", __func__, i, i, response[i]);
    }
    if ((response_len >= 2) && response[response_len - 2] == 0x90 && response[response_len - 1] == 0x00) {
        tloge("%s: eSE factory test success\n", __func__);
        return 0;
    }
    for (i = 0; i < sizeof(response_suc); i++) {
        if (response[i] != response_suc[i]) {
            tloge("%s: eSE factory test fail because of compare fail\n", __func__);
            return -1;
        }
    }

    tloge("%s: eSE factory test success\n", __func__);
    return 0;
}

int p61_scard_connect(int reader_id, void *p_atr, unsigned int *atr_len)
{
    ESESTATUS status = ESESTATUS_SUCCESS;
    (void)reader_id;
    (void)p_atr;
    (void)atr_len;

    p61_gpio_power(GPIOMUX_HIGH);
    // init ese
    phNxpEse_initParams_p61 initParams;
    memset(&initParams, 0x00, sizeof(phNxpEse_initParams_p61));
    initParams.initMode = P61_ESE_MODE_NORMAL;
    status = phNxpEse_open_p61(initParams);
    if (status != ESESTATUS_SUCCESS && ESESTATUS_BUSY != status) {
        tloge("%s(%d): invalid status(0x%x)!\n", __func__, __LINE__, status);
        goto EndOfTests2;
    }
    status = phNxpEse_init_p61(initParams);
    if (status != ESESTATUS_SUCCESS) {
        tloge("%s(%d): invalid status(0x%x)!\n", __func__, __LINE__, status);
        goto EndOfTests1;
    }
    mIsEseInitialized = true;

    return status;

EndOfTests1:
    phNxpEse_close_p61();
EndOfTests2:
    return status;
}


int p61_scard_disconnect(int reader_id)
{
    ESESTATUS status = ESESTATUS_SUCCESS;
    (void)reader_id;
    status = phNxpEse_deInit_p61();
    status = phNxpEse_close_p61();
    p61_gpio_power(GPIOMUX_LOW);

    return status;
}

int p61_scard_transmit(int reader_id, unsigned char *p_cmd, unsigned int cmd_len,
                unsigned char *p_rsp, unsigned int *rsp_len)
{
    ESESTATUS status = ESESTATUS_SUCCESS;
    phNxpEse_data_p61 cmdData = {cmd_len, p_cmd};
    phNxpEse_data_p61 rspData = {0, NULL};
    (void)reader_id;

    status = phNxpEse_Transceive_p61(&cmdData, &rspData);
    if (status != ESESTATUS_SUCCESS) {
        tloge("%s: transmit failed!!!\n", __FUNCTION__);
    }

    // Copy
    memcpy(p_rsp, rspData.p_data, rspData.len);
    *rsp_len = rspData.len;
    // Free rspData
    if(rspData.p_data != 0)
    {
        phNxpEse_free_p61(rspData.p_data);
    }
    rspData.len = 0;

    return status;
}