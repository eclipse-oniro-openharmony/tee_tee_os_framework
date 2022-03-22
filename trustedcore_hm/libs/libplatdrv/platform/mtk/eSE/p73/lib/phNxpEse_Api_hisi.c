#include <phEseStatus.h>
#include <phNxpEse_Api_hisi.h>
#include <phNxpEse_Internal.h>
#include <log_hisi.h>
#include "tee_log.h"


#define OSU_PROP_CLA 0x80
#define OSU_PROP_INS 0xDF
#define OSU_PROP_RST_P1 0xEF

static bool mIsEseInitialized = false;

int p73_p61_factory_test(void)
{
    unsigned char test_cmd[] = {0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00};
    unsigned char response[256] = {0};
    //unsigned char response_suc[] = {0x6F, 0x10, 0x84, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, 0xA5, 0x04, 0x9F, 0x65, 0x01, 0xFF, 0x90, 0x00};/* PN80T */
    //unsigned char response_suc[] = {0x6F, 0x68, 0x84, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, 0xA5, 0x5C, 0x73, 0x56, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01, 0x60, 0x0B, 0x06,0x09,0x2A,0x86,0x48,0x86,0xFC,0x6B,0x02,0x02,0x03,0x63,0x09,0x06,0x07,0x2A,0x86,0x48,0x86,0xFC,0x6B,0x03,0x64,0x16,0x06,0x09,0x2a,0x86,0x48,0x86,0xFC,0x6B,0x04,0x02,0x55,0x06,0x09,0x2a,0x86,0x48,0x86,0xfc,0x6B,0x04,0x03,0x70,0x65,0x0d,0x06,0x0b,0x2a,0x86,0x48,0x86,0xfc,0x6b,0x05,0x07,0x02,0x00,0x00,0x66,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x2a,0x02,0x6E,0x01,0x03,0x9f,0x65,0x01,0xff,0x90,0x00};
    unsigned char response_suc[] = {0x6F, 0x78, 0x84, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, 0xA5, 0x6C, 0x73, 0x66, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01, 0x60, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x02, 0x02, 0x03, 0x63, 0x09, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x03, 0x64, 0x16, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x02, 0x55, 0x64, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x03, 0x10, 0x64, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x03, 0x70, 0x65, 0x0E, 0x06, 0x0C, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x05, 0x07, 0x02, 0x00, 0x00, 0x01, 0x66, 0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x2A, 0x02, 0x6E, 0x01, 0x03, 0x9F, 0x65, 0x01, 0xFF, 0x90, 0x00};
    unsigned int response_len = 0;
    int ret = 0;
    int i;

    tloge("%s: eSE factory test begin ~~~~~~~~\n", __func__);

    scard_connect(1, NULL, NULL);
    ret = scard_transmit(1, test_cmd, sizeof(test_cmd), response, &response_len);
    scard_disconnect(1);

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


int p73_scard_connect(int reader_id, void *p_atr, unsigned int *atr_len)
{
    ESESTATUS status = ESESTATUS_SUCCESS;
    tloge("%s(%d): enter!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n", __func__, __LINE__);

    // init ese
    phNxpEse_initParams initParams;
    memset(&initParams, 0x00, sizeof(phNxpEse_initParams));
    initParams.initMode = ESE_MODE_NORMAL;
    status = phNxpEse_open(initParams);
    if (status != ESESTATUS_SUCCESS && ESESTATUS_BUSY != status) {
        tloge("%s(%d): invalid status(0x%x)!\n", __func__, __LINE__, status);
        goto EndOfTests2;
    }
    status = phNxpEse_SetEndPoint_Cntxt(END_POINT_ESE);
    if (status != ESESTATUS_SUCCESS) {
        tloge("%s(%d): invalid status(0x%x)!\n", __func__, __LINE__, status);
        goto EndOfTests1;
    }
    status = phNxpEse_init(initParams);
    if (status != ESESTATUS_SUCCESS) {
        tloge("%s(%d): invalid status(0x%x)!\n", __func__, __LINE__, status);
        goto EndOfTests1;
    }
    status = phNxpEse_ResetEndPoint_Cntxt(END_POINT_ESE);
    if (status != ESESTATUS_SUCCESS) {
        tloge("%s(%d): invalid status(0x%x)!\n", __func__, __LINE__, status);
        phNxpEse_deInit();
        goto EndOfTests;
    }
    mIsEseInitialized = true;

    return status;

EndOfTests:
    phNxpEse_deInit();
EndOfTests1:
    phNxpEse_close(status);
EndOfTests2:
    return status;
}


int p73_scard_disconnect(int reader_id)
{
    ESESTATUS status = ESESTATUS_SUCCESS;
    status = phNxpEse_deInit();
    status = phNxpEse_close(status);

    return status;
}

int p73_scard_transmit(int reader_id, unsigned char *p_cmd, unsigned int cmd_len,
                unsigned char *p_rsp, unsigned int *rsp_len)
{
    ESESTATUS status = ESESTATUS_SUCCESS;
    phNxpEse_data cmdData = {cmd_len, p_cmd};
    phNxpEse_data rspData = {0, NULL};
    tloge("p73_scard_transmit cmd_len=0x%x, p_cmd[0]=0x%x, p_cmd[1]=0x%x\n", cmd_len, p_cmd[0], p_cmd[1]);
    if (*p_cmd == OSU_PROP_CLA && *(p_cmd + 1) == OSU_PROP_INS &&
             *(p_cmd + 2) != OSU_PROP_RST_P1) {
        if(*(p_cmd + 4) != 0) {
          cmdData.len = cmd_len - 5;
          cmdData.p_data = p_cmd + 5;
        } else {
          cmdData.len = cmd_len - 7;
          cmdData.p_data = p_cmd + 7;
        }
    }
    tloge("p73_scard_transmit cmdData.len=0x%x, cmdData.p_data[0]=0x%x, cmdData.p_data[1]=0x%x\n",
        cmdData.len, cmdData.p_data[0], cmdData.p_data[1]);
    status = phNxpEse_Transceive(&cmdData, &rspData);
    if (status != ESESTATUS_SUCCESS) {
        tloge("%s: transmit failed!!!\n", __FUNCTION__);
    }

    // Copy
    memcpy(p_rsp, rspData.p_data, rspData.len);
    *rsp_len = rspData.len;
    // Free rspData
    if(rspData.p_data != 0)
    {
        phNxpEse_free(rspData.p_data);
    }
    rspData.len = 0;

    return status;
}

phNxpEseProto7816_OsType_t GetOsMode(void)
{
  tloge("%s(%d): enter !\n", __func__, __LINE__);
  return phNxpEse_GetOsMode();
}

int p73_EseProto7816_Reset()
{
    ESESTATUS status;
    tloge("%s(%d): enter !\n", __func__, __LINE__);
    phNxpEse_SetEndPoint_Cntxt(0);
    status = phNxpEse_resetJcopUpdate();
    phNxpEse_ResetEndPoint_Cntxt(0);
    tloge("%s(%d): exit status %d !\n", __func__, __LINE__, status);
    return status;
}
