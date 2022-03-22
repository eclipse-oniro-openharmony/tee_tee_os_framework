#include "../../spi/spi.h"
#include "../common/include/gpio.h"
#include <errno.h>
#include <sre_sys.h>
#include <memory.h>
#include "mem_page_ops.h"
#include <legacy_mem_ext.h>
#include <sre_typedef.h>
#include <mem_ops.h>
#include "sre_task.h"
#include "boot_sharedmem.h"
#include "sre_dev_relcb.h"
#include "p61.h"

#define P61_RETURN_OK 0
#define P61_RETURN_ERROR (-1)
#define TEST_LEN  100
#define READ 0
#define WRITE 1
#define HISI_PRINT_FLAG    1
#define P61_DEBUG  1
#define P61_INFO  1
#define ESE_INFO_LEN 11
#define RAM_ADDR_ESE_CONFIG         (0x367FFC00)        //eSE use 0x365FFC00~0x365FFCFF
#define READY 1
#define NOT_READY 0
#define ERROR (-1)
#define MAX_FRAME_SIZE  300
#define FRAME_HEADER_SIZE 3
#define MAX_DATA_SIZE (MAX_FRAME_SIZE - FRAME_HEADER_SIZE)

#ifndef SE_SUPPORT_SN110
#define scard_support_mode p61_scard_support_mode
#define scard_connect p61_scard_connect
#define scard_disconnect p61_scard_disconnect
#define scard_transmit p61_scard_transmit
#define scard_send p61_scard_send
#define scard_receive p61_scard_receive
#define scard_get_status p61_scard_get_status
#define p61_factory_test p61_p61_factory_test
void alloc_mem(void);
void free_mem(void);
#endif

extern void uart_printf_func(const char *fmt, ...);

#if (HISI_PRINT_FLAG & P61_DEBUG)
#define HISI_PRINT_DEBUG uart_printf_func
#else
#define HISI_PRINT_DEBUG(exp, ...)
#endif

#if (HISI_PRINT_FLAG & P61_INFO)
#define HISI_PRINT_INFO uart_printf_func
#else
#define HISI_PRINT_INFO(exp, ...)
#endif

#if (HISI_PRINT_FLAG)
#define HISI_PRINT_WARRING uart_printf_func
#else
#define HISI_PRINT_WARRING(exp, ...)
#endif

#if (HISI_PRINT_FLAG)
#define HISI_PRINT_ERROR uart_printf_func
#else
#define HISI_PRINT_ERROR(exp, ...)
#endif

typedef unsigned char UINT8;

unsigned int spi_bus_addr = 0;
unsigned int gpio_spi_cs;
unsigned int gpio_ese_irq;
unsigned int gpio_ese_reset;
unsigned int svdd_pwr_req_need;        // 1: needed;   0: not needed;
unsigned int gpio_svdd_pwr_req;
unsigned int spi_switch_need;          // 1: needed;   0: not needed;
unsigned int gpio_spi_switch;
unsigned int nfc_ese_num = 0;
unsigned int nfc_ese_type = 0;

static int ese_init = NOT_READY;

void p61_spidev3_cs_set(u32 control);
static struct spi_config_chip chip_info = {
    .hierarchy = SSP_MASTER,
    .slave_tx_disable = 1,
    .cs_control = p61_spidev3_cs_set,
};

static struct spi_device spi = {
    .max_speed_hz = 4000000,
    .mode = SPI_MODE_0,
    .bits_per_word = 8,
    .controller_data = &chip_info,
};
unsigned char *apduBuffer;
unsigned char *apduBuffer1;
unsigned char *gRecvBuff;
unsigned char *checksum;
int apduBufferidx = 0;
int apduBufferlen = 256;
const unsigned char PH_SCAL_T1_CHAINING = 0x20;
const unsigned char PH_SCAL_T1_SINGLE_FRAME = 0x00;
const char PH_SCAL_T1_R_BLOCK = 0x80;
const char PH_SCAL_T1_S_BLOCK = 0xC0;
const char PH_SCAL_T1_HEADER_SIZE_NO_NAD = 0x02;
static unsigned char seqCounterCard = 0;
static unsigned char seqCounterTerm = 1;
unsigned int ifs = 254;
short headerSize = 3;
unsigned char sof = 0xA5;
unsigned char csSize = 1;
const char C_TRANSMIT_NO_STOP_CONDITION = 0x01;
const char C_TRANSMIT_NO_START_CONDITION = 0x02;
const char C_TRANSMIT_NORMAL_SPI_OPERATION = 0x04;

typedef struct respData {
    unsigned char *data;
    int len;
} respData_t;

respData_t *gStRecvData;
unsigned char *gSendframe;
char *gDataPackage;

#define MEM_CHUNK_SIZE (256)
unsigned char *lastFrame;
int lastFrameLen;
void init(void);
unsigned char helperComputeLRC(unsigned char data[], int offset, int length);
void receiveAcknowledge(void);
void receiveAndCheckChecksum(short rPcb, short rLen, unsigned char data[], int len);
respData_t  *receiveHeader(void);
respData_t  *receiveFrame(short rPcb, short rLen);
int send(unsigned char **data, unsigned char mode, int len);
int receive(unsigned char **data, int len, unsigned char mode);
respData_t  *receiveChainedFrame(short rPcb, short rLen);
int sendFrame(const char data[], unsigned char mode, unsigned int count);
void sendAcknowledge(void);
static int p61_dev_write(const char  *buf,int count);
static int p61_dev_read(char  *buf, int count);
#ifndef SE_SUPPORT_SN110
static respData_t *p61_dev_receiveData_internal(void);
static void hex_print(unsigned char *buf, int blen, int opcode);
#endif
void p61_gpio_control(int gpio, int control);
void p61_load_config(void);
int scard_release_cb(void *data);
int sendChainedFrame(const char data[], unsigned int len);


struct p61_control {
    struct spi_message msg;
    struct spi_transfer transfer;
    unsigned char *tx_buff;
    unsigned char *rx_buff;
};

void p61_load_config(void)
{
    UINT32 ese_info_arr[ESE_INFO_LEN];
    UINT8 spi_bus = 0xff;
    int i = 0;
    memset(ese_info_arr, 0, ESE_INFO_LEN * sizeof(UINT32));
    if (get_shared_mem_info(TEEOS_SHARED_MEM_ESE, ese_info_arr, ESE_INFO_LEN * sizeof(UINT32))) {
        HISI_PRINT_ERROR("map tmp_ese_arr failed\n");
        return;
    }
    HISI_PRINT_INFO("[p61_load_config]tmp_ese_arr=%d.\n", ese_info_arr);
    HISI_PRINT_INFO("[p61_load_config]memcpy ok! \n");
    for (i = 0; i < ESE_INFO_LEN; i++) {
        if (0xffffffff != ese_info_arr[i]) {
            break;
        }
    }
    if (ESE_INFO_LEN == i) {
        ese_init = ERROR;
        HISI_PRINT_ERROR("[p61_load_config]get all ff value. means ese_init error!\n");
        return;
    }
    HISI_PRINT_INFO("[p61_load_config]load config start! \n");
    gpio_spi_cs = (unsigned int)ese_info_arr[1];
    gpio_ese_irq = (unsigned int)ese_info_arr[2];
    gpio_ese_reset = (unsigned int)ese_info_arr[3];
    svdd_pwr_req_need = (unsigned int)ese_info_arr[4];
    gpio_svdd_pwr_req = (unsigned int)ese_info_arr[5];
    spi_switch_need = (unsigned int)ese_info_arr[6];
    gpio_spi_switch = (unsigned int)ese_info_arr[7];
    nfc_ese_num = (unsigned int)ese_info_arr[8];
    nfc_ese_type = (unsigned int)ese_info_arr[9];
    spi_bus = ese_info_arr[0];
    switch (spi_bus) {
    case 0:
        spi_bus_addr = REG_BASE_SPI0;
        break;
    case 1:
        spi_bus_addr = REG_BASE_SPI1;
        break;
    case 2:
        spi_bus_addr = REG_BASE_SPI2;
        break;
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
    case 3:
        spi_bus_addr = REG_BASE_SPI3;
        break;
#endif
    default:
        HISI_PRINT_ERROR("[p61_load_config]SPI%d is not supportted now in TEE \n", spi_bus);
        spi_bus_addr = 0;
        ese_init = ERROR;
        return;
    }
    //set cs to gpio. and use spi driver to simulate cs.
    gpio_set_mode(gpio_spi_cs, GPIOMUX_M0);
    ese_init = READY;
    HISI_PRINT_INFO("[p61_load_config]spi_bus=%d.\n", spi_bus);
    HISI_PRINT_INFO("[p61_load_config]spi_bus_addr=0x%x.\n", spi_bus_addr);
    HISI_PRINT_INFO("[p61_load_config]gpio_spi_cs=%d.\n", gpio_spi_cs);
    HISI_PRINT_INFO("[p61_load_config]gpio_ese_irq=%d.\n", gpio_ese_irq);
    HISI_PRINT_INFO("[p61_load_config]gpio_ese_reset=%d.\n", gpio_ese_reset);
    HISI_PRINT_INFO("[p61_load_config]svdd_pwr_req_need=%d.\n", svdd_pwr_req_need);
    HISI_PRINT_INFO("[p61_load_config]gpio_svdd_pwr_req=%d.\n", gpio_svdd_pwr_req);
    HISI_PRINT_INFO("[p61_load_config]spi_switch_need=%d.\n", spi_switch_need);
    HISI_PRINT_INFO("[p61_load_config]gpio_spi_switch=%d.\n", gpio_spi_switch);
    HISI_PRINT_INFO("[p61_load_config]nfc_ese_num=%d.\n", nfc_ese_num);
    HISI_PRINT_INFO("[p61_load_config]nfc_ese_type=%d.\n", nfc_ese_type);
    return;
}

void p61_gpio_control(int gpio, int control)
{
    gpio_set_direction_output(gpio);
    if (GPIOMUX_HIGH == control) {
        gpio_set_value(gpio, GPIOMUX_HIGH);
    } else if (GPIOMUX_LOW == control) {
        gpio_set_value(gpio, GPIOMUX_LOW);
    } else {
        HISI_PRINT_ERROR("[p61_gpio_control]invalid parameter\n");
    }
    HISI_PRINT_INFO("[p61_gpio_control]gpio%d now is: %d\n", gpio, gpio_get_value(gpio));
}

void p61_spidev3_cs_set(u32 control)
{
    gpio_set_mode(gpio_spi_cs, GPIOMUX_M0);
    gpio_set_direction_output(gpio_spi_cs);
    if (GPIOMUX_HIGH == control) {
        gpio_set_value(gpio_spi_cs, GPIOMUX_HIGH);
    } else if (GPIOMUX_LOW == control) {
        gpio_set_value(gpio_spi_cs, GPIOMUX_LOW);
    } else {
        HISI_PRINT_ERROR("[p61_spidev3_cs_set]invalid parameter\n");
    }
    //HISI_PRINT_ERROR("[p61_spidev3_cs_set]p61 CS gpio now is: %d\n", gpio_get_value(GPIO_SPI1_CS));
    }
#ifndef SE_SUPPORT_SN110
/**
     * Entry point function for receiving data. Based on the PCB byte this function
     * either receives a single frame or a chained frame.
     *
     */
static int p61_receive_data(char  *buf, int *count)
{
    if (NULL == buf || NULL == count) {
        HISI_PRINT_ERROR("Null Pointer when p61_receive_data!\n");
        return -1;
    }
    HISI_PRINT_INFO(" p61 receive Data -Enter\n");
    //spi_v500_init(spi_bus_addr, &spi);
    respData_t *rsp = p61_dev_receiveData_internal();

    if (rsp != NULL) {
        HISI_PRINT_DEBUG(" rsp=%p data=%p  gstrecv=%p~~\n", rsp, rsp->data, gStRecvData);
        *count =  rsp->len;
        if (0 < *count) {
            memcpy(buf, rsp->data, *count);
        }
        if (rsp != gStRecvData) {
            SRE_MemFree(0, rsp->data);
            SRE_MemFree(0, rsp);
            HISI_PRINT_ERROR(" free mem~~\n");
        }
    } else {
        *count = 0;
    }
    //spi_v500_exit(spi_bus_addr);
    return *count;
}

static respData_t *p61_dev_receiveData_internal(void)
{
    short rPcb = 0;
    short rLen = 0;
    respData_t *header = NULL;
    respData_t *respData = NULL;
    unsigned char *wtx = NULL;
    unsigned char *data = NULL;
    unsigned char *data1 = NULL;
    int len = 0;
    int len1 = 0;
    int ret;

Start:
    HISI_PRINT_DEBUG(" p61 receiveData -Enter\n");

    // receive the T=1 header
    header = (respData_t *)receiveHeader();
    if (header == NULL) {
        HISI_PRINT_ERROR("ERROR:Failed to receive header data\n");
        return NULL;
    }
    rPcb = header->data[0];
    rLen = (short)(header->data[1] & 0xFF);
    HISI_PRINT_DEBUG("p61 ireceive header data rPcb = 0x%x , rLen = %d\n", rPcb, rLen);


    //check the header if wtx is requested
    if ((rPcb & PH_SCAL_T1_S_BLOCK) == (unsigned char)PH_SCAL_T1_S_BLOCK) {
        HISI_PRINT_DEBUG("receiveDatav - WTX requested\n");
        data = gRecvBuff;
        len = 1;
        HISI_PRINT_DEBUG("receiveDatav - WTX1 requested\n");
        receive(&data, len, C_TRANSMIT_NO_STOP_CONDITION | C_TRANSMIT_NO_START_CONDITION);
        HISI_PRINT_DEBUG("receiveDatav - WTX2 requested\n");
        receiveAndCheckChecksum(rPcb, rLen, data, len);
        HISI_PRINT_DEBUG("receiveDatav - WTX3 requested\n");
        HISI_PRINT_DEBUG("value is %x %x", data[0], data[1]);
        wtx = gRecvBuff;
        wtx[0] = 0x00;
        wtx[1] = 0xE3;
        wtx[2] = 0x01;
        wtx[3] = 0x01;
        wtx[4] = 0xE3;
        len1 = 5;
        /*SRE_DelayUs(300);*/
        SRE_DelayMs(1);
        ret = send(&wtx, C_TRANSMIT_NORMAL_SPI_OPERATION, len1);
        if (ret == -1) {
            HISI_PRINT_ERROR("p61_dev_receiveData_internal send() FAILED!!!\n");
        }
        /*SRE_DelayUs(300);*/
        SRE_DelayMs(1);
        goto Start;
    }

    //check the header if retransmit is requested
    if ((rPcb & PH_SCAL_T1_R_BLOCK) == (unsigned char)PH_SCAL_T1_R_BLOCK) {
        HISI_PRINT_DEBUG("Retransmit is requested\n");

        data1 = (unsigned char *)SRE_MemAlloc(0, 0, 1);
        if (data1 == NULL) {
            HISI_PRINT_ERROR("p61_dev_receiveData_internal 1-KMALLOC FAILED!!!\n");
            return NULL;
        }
        len1 = 1;
        receiveAndCheckChecksum(rPcb, rLen, data1, len1);

        /*SRE_DelayUs(300);*/
        SRE_DelayMs(1);
        (void)send(&lastFrame, C_TRANSMIT_NORMAL_SPI_OPERATION, lastFrameLen);
        hex_print(lastFrame,  lastFrameLen, WRITE);
        /*SRE_DelayUs(300);*/
        SRE_DelayMs(1);
        SRE_MemFree(0, data1);
        goto Start;
    }

    //check the PCB byte and receive the rest of the frame
    if ((rPcb & PH_SCAL_T1_CHAINING) == (unsigned char)PH_SCAL_T1_CHAINING) {
        HISI_PRINT_DEBUG("p61 Chained Frame Requested\n");

        return receiveChainedFrame(rPcb, rLen);

    } else {
        HISI_PRINT_DEBUG("p61 receiveFrame Requested\n");
        respData = receiveFrame(rPcb, rLen);
        HISI_PRINT_DEBUG("p61 receive value 0x%x \n", respData->data[0]);
        SRE_MemFree(0, apduBuffer);
        apduBuffer = NULL;
        return respData;
    }
    return NULL;
}
#endif
/**
    * This function is used to receive a single T=1 frame
    *
    * @param rPcb
    *            PCB field of the current frame
    * @param rLen
    *            LEN field of the current frame
    * @param filp
    * 			 File pointer
    */

respData_t *receiveFrame(short rPcb, short rLen)
{
    respData_t *respData = NULL;
    HISI_PRINT_DEBUG("receiveFrame -Enter\n");
    respData = gStRecvData;
    respData->data = gRecvBuff;
    respData->len = rLen;
    // modify the card send sequence counter
    seqCounterCard = (seqCounterCard ^ 1);

    // receive the DATA field and check the checksum
    (void)receive(&(respData->data), respData->len, C_TRANSMIT_NO_STOP_CONDITION | C_TRANSMIT_NO_START_CONDITION);

    receiveAndCheckChecksum(rPcb, rLen, respData->data, respData->len);

    HISI_PRINT_DEBUG("receiveFrame -Exit\n");

    return respData;
}

/**
     * This function is used to receive a chained frame.
     *
     * @param rPcb
     *            PCB field of the current frame
     * @param rLen
     *            LEN field of the current frame
     * @param filp
     *            File pointer
     */

respData_t *receiveChainedFrame(short rPcb, short rLen)
{
    respData_t *data = NULL;
    respData_t *header = NULL;
    respData_t *respData = NULL;
    respData_t *apdbuff = NULL;
    unsigned char *apduBuffer_temp = NULL;
    HISI_PRINT_DEBUG("p61 receiveChainedFrame -Enter\n");
    // receive a chained frame as long as chaining is indicated in the PCB
    do {
        // receive the DATA field of the current frame
        data = receiveFrame(rPcb, rLen);
        if(NULL == data || NULL == data->data)
        {
            HISI_PRINT_ERROR( "receiveChainedFrame data is NULL!!!\n");
            return NULL;
        }

        // write it into an apduBuffer memory
        if (data->len > (apduBufferlen - apduBufferidx)) {
            apduBufferlen += MEM_CHUNK_SIZE;
            apduBuffer_temp = (unsigned char *)SRE_MemAlloc(0, 0, apduBufferlen);
            if (apduBuffer_temp == NULL) {
                HISI_PRINT_ERROR("receiveChainedFrame apduBuffer_temp-KMALLOC FAILED!!!\n");
                return NULL;
            }
            memset(apduBuffer_temp, 0, apduBufferlen);
            memcpy(apduBuffer_temp, apduBuffer, apduBufferidx);
            SRE_MemFree(0, apduBuffer);
            apduBuffer = apduBuffer_temp;
            apduBuffer_temp = NULL;
        }

        memcpy((apduBuffer + apduBufferidx), data->data, data->len);

        //update the index to next free slot
        apduBufferidx += data->len;

        // send the acknowledge for the current frame
        sendAcknowledge();

        // igeceive the header of the next frame
        header = receiveHeader();


        if (NULL == header || NULL == header->data) {
            HISI_PRINT_ERROR("header pointer is NULL!!!\n");
            return NULL;
        }

        rPcb = header->data[0];
        rLen = (header->data[1] & 0xFF);

    }while ((rPcb & PH_SCAL_T1_CHAINING) == PH_SCAL_T1_CHAINING);


    // receive the DATA field of the last frame

    respData = receiveFrame(rPcb, rLen);
    if (respData == NULL) {
        HISI_PRINT_ERROR("receiveChainedFrame respData is NULL!!!\n");
        return NULL;
    }

    if (respData->len > (apduBufferlen - apduBufferidx)) {

        apduBufferlen += MEM_CHUNK_SIZE;

        apduBuffer1 = (unsigned char *)SRE_MemAlloc(0, 0, apduBufferidx + respData->len);
        if (apduBuffer1 == NULL) {
            HISI_PRINT_ERROR("receiveChainedFrame 1-KMALLOC FAILED!!!\n");
            return NULL;
        }

        memset(apduBuffer1, 0, apduBufferidx + respData->len);
        memcpy(apduBuffer1, apduBuffer, apduBufferidx);

        // append the received data to the apduBuffer memory

        memcpy((apduBuffer1 + apduBufferidx), respData->data, respData->len);

        SRE_MemFree(0, apduBuffer);
        //add
        apduBuffer = apduBuffer1;
        apduBuffer1 = NULL;
    } else {
        memcpy(apduBuffer + apduBufferidx, respData->data, respData->len);
    }


    //update the index to next free slot
    apduBufferidx += respData->len;

    if (NULL != respData && NULL != respData->data) {
        SRE_MemFree(0, respData->data);
        SRE_MemFree(0, respData);
    }

    // return the entire received apdu
    apdbuff = (respData_t *)SRE_MemAlloc(0, 0, sizeof(respData_t));
    if (apdbuff == NULL) {
        HISI_PRINT_ERROR("receiveChainedFrame 2-KMALLOC FAILED!!!\n");
        return NULL;
    }

    apdbuff->data = (unsigned char *)SRE_MemAlloc(0, 0, apduBufferidx);
    if (apdbuff->data == NULL) {
        HISI_PRINT_ERROR("receiveChainedFrame 3-KMALLOC FAILED!!!\n");
        SRE_MemFree(0, apdbuff);
        return NULL;
    }

    memcpy(apdbuff->data, apduBuffer, apduBufferidx);
    apdbuff->len = apduBufferidx;
    SRE_MemFree(0, apduBuffer);
    apduBuffer = NULL;
    HISI_PRINT_DEBUG("p61 receiveChainedFrame -Exit\n");
    return apdbuff;
}
/**
    * This function is used to send an acknowledge for an received I frame
    * in chaining mode.
    *
    */
void sendAcknowledge(void)
{
    unsigned char ack[4];
    int ret;
    HISI_PRINT_DEBUG("sendAcknowledge - Enter\n");

    // prepare the acknowledge and send it

    ack[0] = 0x00;
    ack[1] = (PH_SCAL_T1_R_BLOCK | (seqCounterCard << 4));
    ack[2] = 0x00;
    ack[3] = helperComputeLRC(ack, 0, sizeof(ack) / sizeof(ack[0]) - 2);

    ret = send((unsigned char **)&ack, C_TRANSMIT_NORMAL_SPI_OPERATION, sizeof(ack) / sizeof(ack[0]));
    if (ret == -1) {
        HISI_PRINT_ERROR("sendAcknowledge - Error\n");
    }

    HISI_PRINT_DEBUG("sendAcknowledge - Exit\n");

}
#ifndef SE_SUPPORT_SN110
/**
    * This function sends either a chained frame or a single T=1 frame
    *
    * @param buf
    *            the data to be send
    *
    */
static int p61_send_data(const char  *buf, unsigned int count)
{
    int ret = -1;
    if (NULL == buf) {
        HISI_PRINT_ERROR("Null Pointer when p61_send_data!\n");
        return ret;
    }
    HISI_PRINT_INFO(" p61 send data count=%d-Enter\n", count);
    //spi_v500_init(spi_bus_addr, &spi);
    init();

    //HISI_PRINT_DEBUG("p61 p61_dev_sendData %d - Enter \n",count);
    if (count <= ifs) {
        ret = sendFrame(buf, PH_SCAL_T1_SINGLE_FRAME, count);
        HISI_PRINT_DEBUG("Vaue of count_status is %d \n", ret);
    } else {
        //return sendChainedFrame(data);
        ret = sendChainedFrame(buf, count);
    }
    //spi_v500_exit(spi_bus_addr);
    HISI_PRINT_DEBUG("p61_dev_sendData: count_status is %d \n", ret);
    return ret;
}
#endif
/**
     * This function is used to send a chained frame.
     *
     * @param data
     *            the data to be send
     */
int sendChainedFrame(const char data[], unsigned int len)
{

    int count_status = 0 ;
    unsigned int length = len;
    int offset = 0;
    int ret = 0;
    char *lastDataPackage = NULL;
    char *dataPackage = NULL;
    HISI_PRINT_DEBUG("sendChainedFrame - Enter\n");
    if (len < ifs) {
        HISI_PRINT_DEBUG("no need to sendChainedFrame!\n");
        return -1;
    }
    dataPackage = gDataPackage;
    do {
        HISI_PRINT_DEBUG("sendChainedFrame \n");
        // send a chained frame and receive the acknowledge
        memcpy(&dataPackage[0], &data[offset], ifs);

        count_status = sendFrame(dataPackage, PH_SCAL_T1_CHAINING, ifs);
        if (count_status == 0) {
            HISI_PRINT_ERROR("ERROR1: Failed to send Frame\n");
            return -1;
        }
        receiveAcknowledge();
        /*SRE_DelayUs(300);*/
        SRE_DelayMs(1);
        length = length - ifs;
        offset = offset + ifs;
        ret += count_status;
    } while (length > ifs);

    // send the last frame
    lastDataPackage = gDataPackage;
    memcpy(&lastDataPackage[0], &data[offset], length);

    count_status = sendFrame(lastDataPackage, PH_SCAL_T1_SINGLE_FRAME, length);

    if (count_status == 0)

    {
        HISI_PRINT_ERROR("ERROR2:Failed to send Frame\n");
        return -1;
    }
    HISI_PRINT_DEBUG("sendChainedFrame - Exit\n");
    ret += count_status;
    return ret;
}
/**
     * This function is used to receive an Acknowledge of an I frame
     *
     */
void receiveAcknowledge(void)
{
    respData_t *header = NULL;
    short rPcb = 0;
    short rLen = 0;
    int len = 1;
    unsigned char *cs = NULL;
    HISI_PRINT_DEBUG("receiveAcknowledge - Enter\n");
    cs = gRecvBuff;
    header = (respData_t *) receiveHeader();

    if (header == NULL)
    return;

    rPcb = (header->data[0] & 0xFF);
    rLen = (header->data[1] & 0xFF);
    receiveAndCheckChecksum(rPcb, rLen, cs, len);
    HISI_PRINT_DEBUG("receiveAcknowledge - Exit\n");
}

/**
 * This function is used to receive the header of the next T=1 frame.
 * If no data is available the function polls the data line as long as it receives the
 * start of the header and then receives the entire header.
 *
 */
respData_t *receiveHeader(void)
{
    int count_status = 0;
    //unsigned char *ready=NULL;
    respData_t *header = NULL;
    int len = 1, times = 3000;
    HISI_PRINT_DEBUG("receiveHeader - Enter\n");
    header = gStRecvData;
    header->data = gRecvBuff;
    header->len = PH_SCAL_T1_HEADER_SIZE_NO_NAD;
    count_status = receive(&gRecvBuff, len, C_TRANSMIT_NO_STOP_CONDITION);
    HISI_PRINT_DEBUG("count_status = %d, sof is :0x%x\n", count_status, gRecvBuff[0]);

    // check if we received ready
    while ((count_status == -1 || gRecvBuff[0] != sof) && times--) {
        HISI_PRINT_DEBUG("SOF not found\n");
        // receive one byte and keep SS line low
        count_status = receive(&gRecvBuff, len, C_TRANSMIT_NO_STOP_CONDITION | C_TRANSMIT_NO_START_CONDITION);
        HISI_PRINT_DEBUG("count_status = %d, in While SOF is : 0x%x \n", count_status,	gRecvBuff[0]);
        /*SRE_DelayUs(100);*/    //100*30us.
        SRE_DelayMs(1);
    }
    if (times <= 0) {
        HISI_PRINT_ERROR("ERROR:Failed to receive SOF\n");
        return NULL;
    } else {
        HISI_PRINT_INFO("SOF FOUND\n");
    }

    // we received ready byte, so we can receive the rest of the header and keep SS line low
    count_status = receive(&(header->data), header->len , C_TRANSMIT_NO_STOP_CONDITION | C_TRANSMIT_NO_START_CONDITION);
    if (count_status == -1) {
        HISI_PRINT_ERROR("ERROR:Failed to receive data from device\n");
        return NULL;
    }
    HISI_PRINT_DEBUG("receiveHeader -Exit\n");

    return header;
}
/**
     * This function is used to receive and check the checksum of the T=1 frame.
     *
     * @param rPcb
     *            PCB field of the current frame
     * @param rLen
     *            LEN field of the current frame
     * @param data
     *            DATA field of the current frame
     * @param dataLength
     *
     * @param filp
     * 			  File pointer
     *
     */
void receiveAndCheckChecksum(short rPcb, short rLen, unsigned char data[], int dataLength)
{
    int lrc = rPcb ^ rLen;
    int receivedCs = 0;
    int expectedCs = 0;
    HISI_PRINT_DEBUG("receiveAndCheckChecksum -Enter\n");

    dataLength = dataLength - csSize;

    // compute the expected CS

    expectedCs = 0x5A ^ lrc ^ helperComputeLRC(data, 0, dataLength);

    // receive the T=1 CS
    receive(&checksum, csSize, C_TRANSMIT_NO_START_CONDITION);

    receivedCs = checksum[0];

    // compare the chechsums
    if (expectedCs != receivedCs) {
        HISI_PRINT_DEBUG("expectedCs =%d, receivedCs =%d, Checksum error \n", expectedCs, receivedCs);
    }

    HISI_PRINT_DEBUG("receiveAndCheckChecksum -Exit\n");
}
/**
     * Basic send function which directly calls the spi bird wrapper function
     *
     * @param data
     *            the data to be send
     *
     */
int send(unsigned char **data, unsigned char mode, int len)
{
    int count = 0;
    HISI_PRINT_DEBUG("send - Enter len=%d, mode = 0x%x \n", len, mode);

    // call to the spi bird wrapper
    count = p61_dev_write((char *)*data, len);

    if (count == 0) {
        HISI_PRINT_ERROR("ERROR:Failed to send data to device\n");
        return -1;
    }
    return count;
}

int receive(unsigned char **data, int len, unsigned char mode)
{
    static int count_status;
    HISI_PRINT_DEBUG("receive -Enter mode = 0x%x \n", mode);
    count_status = p61_dev_read((char *)*data, len);
    if (count_status <= 0) {
        HISI_PRINT_ERROR("ERROR:Failed to receive data from device\n");
        return -1;
    }

    HISI_PRINT_DEBUG("receive -Exit count=%d\n", count_status);

    return count_status;

}

static int p61_dev_write(const char *buf, int count)
{
    int ret = P61_RETURN_ERROR;
    if (NULL == buf) {
        HISI_PRINT_ERROR("Null Pointer when p61_dev_write!\n");
        return ret;
    }
    struct spi_transfer t = {
        .tx_buf = buf,
        .len = count,
        .delay_usecs = 0,
        .cs_change = 1, // pull down cs every transfer
    };
    struct spi_message  m = {
        .transfers = &t,
        .transfer_num = 1, // transfer num
        .actual_length = 0,
        .status = 0,
    };
    u32 p61_spi_bus_addr = (u32)spi_bus_addr;

    ret = hisi_spi_init(p61_spi_bus_addr, &spi);
    if (ret != P61_RETURN_OK)
        return P61_RETURN_ERROR;
    ret = hisi_spi_polling_transfer(p61_spi_bus_addr, &m);
    if (ret != P61_RETURN_OK) {
        hisi_spi_exit(p61_spi_bus_addr);
        return P61_RETURN_ERROR;
    }
    hisi_spi_exit(p61_spi_bus_addr);
    if (m.status != P61_RETURN_OK)
        return ret;

    return count;
}

static int p61_dev_read(char  *buf, int count)
{
    int ret = P61_RETURN_ERROR;
    if (NULL == buf) {
        HISI_PRINT_ERROR("Null Pointer when p61_dev_read!\n");
        return ret;
    }
    struct spi_transfer t = {
        .rx_buf = buf,
        .len = count,
        .delay_usecs = 0,
        .cs_change = 1, // pull down cs every transfer
    };
    struct spi_message  m = {
        .transfers = &t,
        .transfer_num = 1, // transfer num
        .actual_length = 0,
        .status = 0,
    };
    u32 p61_spi_bus_addr = (u32)spi_bus_addr;

    ret = hisi_spi_init(p61_spi_bus_addr, &spi);
    if (ret != P61_RETURN_OK)
        return P61_RETURN_ERROR;

    ret = hisi_spi_polling_transfer(p61_spi_bus_addr, &m);
    if (ret != P61_RETURN_OK) {
        hisi_spi_exit(p61_spi_bus_addr);
        return P61_RETURN_ERROR;
    }
    hisi_spi_exit(p61_spi_bus_addr);
    if (m.status != P61_RETURN_OK)
        return ret;

    return count;
}

/**
 * This function is used to send a single T=1 frame.
 *
 * @param data
 *            the data to be send
 * @param mode
 *            used to signal chaining
 *
 */
int sendFrame(const char data[], unsigned char mode, unsigned int count)
{
    int count_status = 0;
    int len = count + headerSize + csSize;
    unsigned char *frame = NULL;
    HISI_PRINT_DEBUG("sendFrame - Enter\n");
    if (count > MAX_DATA_SIZE) {
        HISI_PRINT_DEBUG("count is overflow!\n");
        return -1;
    }
    frame = gSendframe;
    // update the send sequence counter of the terminal
    seqCounterTerm = (unsigned char)(seqCounterTerm ^ 1);

    // prepare the frame and send it
    frame[0] = 0x5A;
    frame[1] = mode | (seqCounterTerm << 6); //(unsigned char)(mode |(unsigned char) (seqCounterTerm << 6));
    frame[2] = (unsigned char)(count);

    memcpy((frame + 3), data, count);

    frame[count + headerSize] = (unsigned char)helperComputeLRC(frame, 0, count + headerSize - 1);
    lastFrame = frame;
    lastFrameLen = len;
    count_status = send(&frame, C_TRANSMIT_NORMAL_SPI_OPERATION, len);

    if (count_status == 0) {
        HISI_PRINT_ERROR("ERROR:Failed to send device\n");
        return -1;
    }

    HISI_PRINT_DEBUG("sendFrame ret = %d - Exit\n", count_status);
    return count_status;
}
/**
     * Helper function to compute the LRC.
     *
     * @param data
     *            the data array
     * @param offset
     *            offset into the data array
     * @param length
     *            length value
     *
     */
unsigned char helperComputeLRC(unsigned char data[], int offset, int length)
{
    int LRC = 0x5A;
    int i = 0;
    HISI_PRINT_DEBUG("helperComputeLRC - Enter\n");
    for (i = offset; i <= length; i++) {
        LRC = LRC ^ data[i];
    }
    HISI_PRINT_DEBUG("LRC Value is  %x \n", LRC);
    return (unsigned char)LRC;
}
/**
    * This function initializes the T=1 module
    *
    */
void init(void)
{
    HISI_PRINT_DEBUG("init - Enter\n");
    apduBuffer = (unsigned char *) SRE_MemAlloc(0, 0, apduBufferlen);
    if (apduBuffer == NULL) {
        HISI_PRINT_ERROR("init - FAILED TO ALLOCATE MEMORYS \n");
        return;
    }

    memset(apduBuffer, 0, apduBufferlen);

    apduBufferidx = 0;
    seqCounterCard = 0;
    seqCounterTerm = 1;

    HISI_PRINT_DEBUG("init - Exit\n");
}
#ifndef SE_SUPPORT_SN110
static void hex_print(unsigned char *buf, int blen, int opcode)
{
    int i;
    if (NULL == buf) {
        HISI_PRINT_ERROR("Null Pointer when hex_print!\n");
        return;
    }

    if (READ == opcode) {
        HISI_PRINT_INFO("NFCC--->DH#\nread(%d):", blen);
    } else {
        HISI_PRINT_INFO("DH--->NFCC#write(%d):", blen);
    }
    for (i = 0; i < blen; i++) {
        HISI_PRINT_INFO("0x%x ", buf[i]);
    }
    HISI_PRINT_INFO("\n");
}
#endif

#ifdef SE_SUPPORT_SN110
int p61_gpio_power(int control)
{
    /* init ese config if first run */
    if (NOT_READY == ese_init) {
        p61_load_config();
    }
    if (ERROR == ese_init) {
        HISI_PRINT_INFO("[scard_connect]ese_init is error.\n");
        return -1;
    }

    if (svdd_pwr_req_need) {
        p61_gpio_control(gpio_svdd_pwr_req, control);
    }
    if (spi_switch_need) {
        p61_gpio_control(gpio_spi_switch, control);
    }
    HISI_PRINT_INFO("[p61_gpio_power] success\n");
    return 0;
}
#endif

#ifndef SE_SUPPORT_SN110
int p61_factory_test(void)
{
    unsigned char test_cmd[] = {0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00};
    unsigned char response[256] = {0};
    unsigned char response_suc[] = {0x6F, 0x10, 0x84, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, 0xA5, 0x04, 0x9F, 0x65, 0x01, 0xFF, 0x90, 0x00};
    unsigned int response_len = 0;
    unsigned int i;
    int ret = 0; 

    HISI_PRINT_INFO("%s: eSE factory test begin ~~~~~~~~\n", __func__);

    scard_connect(0, NULL, NULL);
    ret = scard_transmit(0, test_cmd, sizeof(test_cmd), response, &response_len);

    for (i = 0; i < response_len; i++) {
        HISI_PRINT_ERROR("%s:len=%d, response[%d] = 0x%x\n", __func__, response_len, i, response[i]);
    }

    scard_disconnect(0);

    if (ret) {
        HISI_PRINT_ERROR("%s: eSE factory test fail because of transmit fail\n", __func__);
        return -1;
    }

    // compare
    for (i = 0; i < sizeof(response_suc); i++) {
        if (response[i] != response_suc[i]) {
            HISI_PRINT_ERROR("%s: eSE factory test fail because of compare fail\n", __func__);
            return -1;
        }
    }

    HISI_PRINT_ERROR("%s: eSE factory test success\n", __func__);
    return 0;
}

void p61_open(void)
{
    HISI_PRINT_INFO("p61_open\n");
    alloc_mem();
}

void p61_close(void)
{
    HISI_PRINT_INFO("p61_close\n");
    free_mem();
}

void alloc_mem(void)
{
    gRecvBuff = (unsigned char *)SRE_MemAlloc(0, 0, MAX_FRAME_SIZE);
    gStRecvData = (respData_t *)SRE_MemAlloc(0, 0, sizeof(respData_t));
    checksum = (unsigned char *)SRE_MemAlloc(0, 0, csSize);
    gSendframe = (unsigned char *)SRE_MemAlloc(0, 0, MAX_FRAME_SIZE);
    gDataPackage = (char *)SRE_MemAlloc(0, 0, MAX_FRAME_SIZE);
}
void free_mem(void)
{
    if (gRecvBuff) {
        SRE_MemFree(0, gRecvBuff);
        gRecvBuff = NULL;
    }
    if (gStRecvData) {
        SRE_MemFree(0, gStRecvData);
        gStRecvData = NULL;
    }
    if (checksum) {
        SRE_MemFree(0, checksum);
        checksum = NULL;
    }
    if (gSendframe) {
        SRE_MemFree(0, gSendframe);
        gSendframe = NULL;
    }
    if (gDataPackage) {
        SRE_MemFree(0, gDataPackage);
        gDataPackage = NULL;
    }
}

int scard_connect(int reader_id, void *p_atr, unsigned int *atr_len)
{
    /* init ese config if first run */
    if(p_atr != NULL && atr_len != NULL) {
       HISI_PRINT_INFO("%s: scard_connect reader_id = %d \n", __func__, reader_id); 
    }
    if (NOT_READY == ese_init) {
        p61_load_config();
    }
    if (ERROR == ese_init) {
        HISI_PRINT_INFO("[scard_connect]ese_init is error.\n");
        return -1;
    }

    if (svdd_pwr_req_need) {
        p61_gpio_control(gpio_svdd_pwr_req, GPIOMUX_HIGH);
    }
    if (spi_switch_need) {
        p61_gpio_control(gpio_spi_switch, GPIOMUX_HIGH);
    }
    p61_open();

    /* Note: put this at the end of this function after connect successfully,
     * this register se disconnect callback to current task,
     * in case of se disconnect call missing when task exit */
    int ret = task_register_devrelcb((DEV_RELEASE_CALLBACK)scard_release_cb, NULL);
    if (ret) {
        (void)scard_disconnect(0);
        HISI_PRINT_ERROR("SRE_TaskRegister_DevRelCb for scard error:%d\n", ret); /*lint !e515 */
        return ret;
    }

    return 0;
}

int scard_disconnect(int reader_id)
{
    HISI_PRINT_INFO("scard_disconnect reader_id = %d \n", reader_id);
    if (ERROR == ese_init) {
        HISI_PRINT_INFO("[scard_disconnect]ese_init is error.\n");
        return -1;
    }

    p61_close();

    if (svdd_pwr_req_need) {
        p61_gpio_control(gpio_svdd_pwr_req, GPIOMUX_LOW);
    }
    if (spi_switch_need) {
        p61_gpio_control(gpio_spi_switch, GPIOMUX_LOW);
    }

    /* unregister se release callback to current task */
    (void)task_unregister_devrelcb((DEV_RELEASE_CALLBACK)scard_release_cb, NULL);

    return 0;
}

int scard_release_cb(void *data)
{
    if(data != NULL){
       HISI_PRINT_INFO("%s: enter \n", __func__);
    }
    return scard_disconnect(0);
}

int scard_transmit(int reader_id , unsigned char *p_cmd , unsigned int cmd_len ,
           unsigned char *p_rsp , unsigned int *rsp_len)
{
    int ret = -1;
    if (NULL == p_cmd || NULL == p_rsp) {
        HISI_PRINT_ERROR("Null Pointer when scard_transmit!\n");
        return ret;
    }
    if (READY != ese_init) {
        HISI_PRINT_ERROR("[scard_transmit]ese_init is not ready.\n");
        return ret;
    }
    HISI_PRINT_INFO("scard_transmit reader_id = %d \n", reader_id);
    hex_print(p_cmd,  cmd_len, WRITE);
    ret = p61_send_data((char *)p_cmd, cmd_len);
    if (ret <= 0) {
        HISI_PRINT_ERROR("ESE apdu send failed\n");
        *rsp_len = 0;
        return -1;
    }
    /*SRE_DelayUs(500);*/
    SRE_DelayMs(10);
    ret = p61_receive_data((char *)p_rsp, (int *)rsp_len);
    if (ret <= 0) {
        HISI_PRINT_ERROR("ESE p61 apdu recieve failed\n");
        return -1;
    }
    hex_print(p_rsp,  ret, READ);

    gpio_set_direction_input(gpio_spi_cs);

    return 0;
}
#endif
int scard_get_ese_type(void)
{
    /* init ese config if first run */
    if (NOT_READY == ese_init) {
        p61_load_config();
    }
    HISI_PRINT_ERROR("scard_get_ese_type enter\n");

#ifdef PLATFORM_NO_HISEE_FLAG
    HISI_PRINT_ERROR("%s: no hisee enter nfc_ese_type=%d\n", __func__, nfc_ese_type);
    if (nfc_ese_type == 1) { /* 1 means ese */
        HISI_PRINT_ERROR("scard_get_ese_type return 1\n");
        return 1; /* 1 means ese */
    } else {
        HISI_PRINT_ERROR("scard_get_ese_type return 0xFF\n");
        return 0xFF; /* 0xFF means no se for use */
    }
#else
    if (nfc_ese_num == 2)
    {
        HISI_PRINT_ERROR("scard_get_ese_type return 2\n");
        return 2;
    }
    else
    {
        /*p61*/
        if (nfc_ese_type == 1)
        {
            HISI_PRINT_ERROR("scard_get_ese_type return 1\n");
            return 1;
        }
        /*hisee*/
        else
        {
            HISI_PRINT_ERROR("scard_get_ese_type return 0\n");
            return 0;
        }
    }
#endif
}
