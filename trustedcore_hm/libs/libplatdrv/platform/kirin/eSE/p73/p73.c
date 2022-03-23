#include "../../spi/spi.h"
#include "../common/include/gpio.h"
#include <errno.h>
#include <sre_sys.h>
#include "mem_page_ops.h"
#include <legacy_mem_ext.h>
#include <sre_typedef.h>
#include <mem_ops.h>
#include <memory.h>
#include "sre_task.h"
#include "boot_sharedmem.h"
#include "p73.h"
#include <log_hisi.h>
#include <phNxpEse_Api_hisi.h>

#define P61_RETURN_OK 0
#define P61_RETURN_ERROR (-1)
#define TEST_LEN  100
#define READ 0
#define WRITE 1
#define ESE_INFO_LEN 10
#define RAM_ADDR_ESE_CONFIG         (0x367FFC00)        //eSE use 0x365FFC00~0x365FFCFF
#define READY 1
#define NOT_READY 0
#define ERROR (-1)
#define MAX_FRAME_SIZE  300
#define FRAME_HEADER_SIZE 3
#define MAX_DATA_SIZE (MAX_FRAME_SIZE - FRAME_HEADER_SIZE)

#define scard_support_mode p73_scard_support_mode
#define scard_send p73_scard_send
#define scard_receive p73_scard_receive
#define scard_get_status p73_scard_get_status

typedef unsigned char UINT8;

unsigned int p73_spi_bus_addr = 0;
unsigned int gpio_spi_cs;
unsigned int gpio_ese_irq;
unsigned int gpio_ese_reset;
unsigned int svdd_pwr_req_need;        // 1: needed;   0: not needed;
unsigned int gpio_svdd_pwr_req;
unsigned int spi_switch_need;          // 1: needed;   0: not needed;
unsigned int gpio_spi_switch;
unsigned int p73_nfc_ese_num = 0;
unsigned int p73_nfc_ese_type = 0;

static int ese_init = NOT_READY;

void p73_spidev3_cs_set(u32 control);
static struct spi_config_chip chip_info = {
    .hierarchy = SSP_MASTER,
    .slave_tx_disable = 1,
    .cs_control = p73_spidev3_cs_set,
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
int p73_apduBufferidx = 0;
int p73_apduBufferlen = 256;
const unsigned char P73_PH_SCAL_T1_CHAINING = 0x20;
const unsigned char P73_PH_SCAL_T1_SINGLE_FRAME = 0x00;
const char P73_PH_SCAL_T1_R_BLOCK = 0x80;
const char P73_PH_SCAL_T1_S_BLOCK = 0xC0;
const char P73_PH_SCAL_T1_HEADER_SIZE_NO_NAD = 0x02;
static unsigned char seqCounterCard = 0;
static unsigned char seqCounterTerm = 1;
unsigned int p73_ifs = 254;
short p73_headerSize = 3;
unsigned char p73_sof = 0xA5;
unsigned char p73_csSize = 1;
const char P73_C_TRANSMIT_NO_STOP_CONDITION = 0x01;
const char P73_C_TRANSMIT_NO_START_CONDITION = 0x02;
const char P73_C_TRANSMIT_NORMAL_SPI_OPERATION = 0x04;

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
void p73_init(void);
unsigned char p73_helperComputeLRC(unsigned char data[], int offset, int length);
void p73_receiveAcknowledge(void);
void p73_receiveAndCheckChecksum(short rPcb, short rLen, unsigned char data[], int len);
respData_t  *p73_receiveHeader(void);
respData_t  *p73_receiveFrame(short rPcb, short rLen);
int p73_send(unsigned char **data, unsigned char mode, int len);
int p73_receive(unsigned char **data, int len, unsigned char mode);
respData_t  *p73_receiveChainedFrame(short rPcb, short rLen);
int p73_sendFrame(const char data[], unsigned char mode, unsigned int count);
void p73_sendAcknowledge(void);
int p61_dev_write(const char  *buf,int count);
int p61_dev_read(char  *buf, int count);
void p73_gpio_control(int gpio, int control);
void p73_load_config(void);
int p73_scard_release_cb(void *data);
int p73_sendChainedFrame(const char data[], unsigned int len);
void p73_alloc_mem(void);
void p73_free_mem(void);

struct p61_control {
    struct spi_message msg;
    struct spi_transfer transfer;
    unsigned char *tx_buff;
    unsigned char *rx_buff;
};

void p73_load_config(void)
{
    UINT32 ese_info_arr[ESE_INFO_LEN];
    UINT8 spi_bus = 0xff;
    int i = 0;

    memset(ese_info_arr, 0, ESE_INFO_LEN * sizeof(UINT32));

    if (get_shared_mem_info(TEEOS_SHARED_MEM_ESE, ese_info_arr, ESE_INFO_LEN * sizeof(UINT32))) {
        HISI_PRINT_ERROR("map tmp_ese_arr failed\n");
        return;
    }

    HISI_PRINT_ERROR("[p73_load_config]tmp_ese_arr=%d.\n", ese_info_arr);


    //memcpy(ese_info_arr, (void *)ese_tmp_addr, ESE_INFO_LEN * sizeof(UINT8));
    HISI_PRINT_ERROR("[p73_load_config]memcpy ok! \n");

    for (i = 0; i < ESE_INFO_LEN; i++) {
        if (0xffffffff != ese_info_arr[i]) {
            break;
        }
    }

    if (ESE_INFO_LEN == i) {
        ese_init = ERROR;
        HISI_PRINT_ERROR("[p73_load_config]get all ff value. means ese_init error!\n");
        return;
    }

    HISI_PRINT_ERROR("[p73_load_config]load config start! \n");


    gpio_spi_cs = (unsigned int)ese_info_arr[1];
    gpio_ese_irq = (unsigned int)ese_info_arr[2];
    gpio_ese_reset = (unsigned int)ese_info_arr[3];
    svdd_pwr_req_need = (unsigned int)ese_info_arr[4];
    gpio_svdd_pwr_req = (unsigned int)ese_info_arr[5];
    spi_switch_need = (unsigned int)ese_info_arr[6];
    gpio_spi_switch = (unsigned int)ese_info_arr[7];
    p73_nfc_ese_num = (unsigned int)ese_info_arr[8];
    p73_nfc_ese_type = (unsigned int)ese_info_arr[9];

    spi_bus = ese_info_arr[0];
    switch (spi_bus) {
        case 0:
            p73_spi_bus_addr = REG_BASE_SPI0;
            break;
        case 1:
            p73_spi_bus_addr = REG_BASE_SPI1;
            break;
        case 2:
            p73_spi_bus_addr = REG_BASE_SPI2;
            break;
        case 3: // add p73_spi_bus_addr 3
            p73_spi_bus_addr = REG_BASE_SPI3;
            break;
    default:
        HISI_PRINT_ERROR("[p73_load_config]SPI%d is not supportted now in TEE \n", spi_bus);
        p73_spi_bus_addr = 0;
        ese_init = ERROR;
        return;
    }

    //set cs to gpio. and use spi driver to simulate cs.
    gpio_set_mode(gpio_spi_cs, GPIOMUX_M0);

    ese_init = READY;

    HISI_PRINT_ERROR("[p73_load_config]spi_bus=%d.\n", spi_bus);
    HISI_PRINT_ERROR("[p73_load_config]p73_spi_bus_addr=0x%x.\n", p73_spi_bus_addr);
    HISI_PRINT_ERROR("[p73_load_config]gpio_spi_cs=%d.\n", gpio_spi_cs);
    HISI_PRINT_ERROR("[p73_load_config]gpio_ese_irq=%d.\n", gpio_ese_irq);
    HISI_PRINT_ERROR("[p73_load_config]gpio_ese_reset=%d.\n", gpio_ese_reset);
    HISI_PRINT_ERROR("[p73_load_config]svdd_pwr_req_need=%d.\n", svdd_pwr_req_need);
    HISI_PRINT_ERROR("[p73_load_config]gpio_svdd_pwr_req=%d.\n", gpio_svdd_pwr_req);
    HISI_PRINT_ERROR("[p73_load_config]spi_switch_need=%d.\n", spi_switch_need);
    HISI_PRINT_ERROR("[p73_load_config]gpio_spi_switch=%d.\n", gpio_spi_switch);
    HISI_PRINT_ERROR("[p73_load_config]p73_nfc_ese_num=%d.\n", p73_nfc_ese_num);
    HISI_PRINT_ERROR("[p73_load_config]p73_nfc_ese_type=%d.\n", p73_nfc_ese_type);

    return;
}

void p73_gpio_control(int gpio, int control)
{
    gpio_set_direction_output(gpio);
    if (GPIOMUX_HIGH == control) {
        gpio_set_value(gpio, GPIOMUX_HIGH);
    } else if (GPIOMUX_LOW == control) {
        gpio_set_value(gpio, GPIOMUX_LOW);
    } else {
        HISI_PRINT_ERROR("[p73_gpio_control]invalid parameter\n");
    }
    HISI_PRINT_INFO("[p73_gpio_control]gpio%d now is: %d\n", gpio, gpio_get_value(gpio));
}

void p73_spidev3_cs_set(u32 control)
{
    gpio_set_mode(gpio_spi_cs, GPIOMUX_M0);
    gpio_set_direction_output(gpio_spi_cs);
    if (GPIOMUX_HIGH == control) {
        gpio_set_value(gpio_spi_cs, GPIOMUX_HIGH);
    } else if (GPIOMUX_LOW == control) {
        gpio_set_value(gpio_spi_cs, GPIOMUX_LOW);
    } else {
        HISI_PRINT_ERROR("[p73_spidev3_cs_set]invalid parameter\n");
    }
    //HISI_PRINT_ERROR("[p73_spidev3_cs_set]p61 CS gpio now is: %d\n", gpio_get_value(GPIO_SPI1_CS));
}

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

respData_t *p73_receiveFrame(short rPcb, short rLen)
{
    respData_t *respData = NULL;
    HISI_PRINT_DEBUG("p73_receiveFrame -Enter\n");
    respData = gStRecvData;
    respData->data = gRecvBuff;
    respData->len = rLen;
    // modify the card send sequence counter
    seqCounterCard = (seqCounterCard ^ 1);

    // receive the DATA field and check the checksum
    (void)p73_receive(&(respData->data), respData->len, P73_C_TRANSMIT_NO_STOP_CONDITION | P73_C_TRANSMIT_NO_START_CONDITION);

    p73_receiveAndCheckChecksum(rPcb, rLen, respData->data, respData->len);

    HISI_PRINT_DEBUG("p73_receiveFrame -Exit\n");

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

respData_t *p73_receiveChainedFrame(short rPcb, short rLen)
{
    respData_t *data = NULL;
    respData_t *header = NULL;
    respData_t *respData = NULL;
    respData_t *apdbuff = NULL;
    unsigned char *apduBuffer_temp = NULL;
    HISI_PRINT_DEBUG("p61 p73_receiveChainedFrame -Enter\n");
    // receive a chained frame as long as chaining is indicated in the PCB
    do {
        // receive the DATA field of the current frame
        data = p73_receiveFrame(rPcb, rLen);
        if(NULL == data || NULL == data->data)
        {
            HISI_PRINT_ERROR( "p73_receiveChainedFrame data is NULL!!!\n");
            return NULL;
        }

        // write it into an apduBuffer memory
        if (data->len > (p73_apduBufferlen - p73_apduBufferidx)) {
            p73_apduBufferlen += MEM_CHUNK_SIZE;
            apduBuffer_temp = (unsigned char *)SRE_MemAlloc(0, 0, p73_apduBufferlen);
            if (apduBuffer_temp == NULL) {
                HISI_PRINT_ERROR("p73_receiveChainedFrame apduBuffer_temp-KMALLOC FAILED!!!\n");
                return NULL;
            }
            memset(apduBuffer_temp, 0, p73_apduBufferlen);
            memcpy(apduBuffer_temp, apduBuffer, p73_apduBufferidx);
            SRE_MemFree(0, apduBuffer);
            apduBuffer = apduBuffer_temp;
            apduBuffer_temp = NULL;
        }

        memcpy((apduBuffer + p73_apduBufferidx), data->data, data->len);

        //update the index to next free slot
        p73_apduBufferidx += data->len;

        // send the acknowledge for the current frame
        p73_sendAcknowledge();

        // igeceive the header of the next frame
        header = p73_receiveHeader();


        if (NULL == header || NULL == header->data) {
            HISI_PRINT_ERROR("header pointer is NULL!!!\n");
            return NULL;
        }

        rPcb = header->data[0];
        rLen = (header->data[1] & 0xFF);

    }while ((rPcb & P73_PH_SCAL_T1_CHAINING) == P73_PH_SCAL_T1_CHAINING);


    // receive the DATA field of the last frame

    respData = p73_receiveFrame(rPcb, rLen);
    if (respData == NULL) {
        HISI_PRINT_ERROR("p73_receiveChainedFrame respData is NULL!!!\n");
        return NULL;
    }

    if (respData->len > (p73_apduBufferlen - p73_apduBufferidx)) {

        p73_apduBufferlen += MEM_CHUNK_SIZE;

        apduBuffer1 = (unsigned char *)SRE_MemAlloc(0, 0, p73_apduBufferidx + respData->len);
        if (apduBuffer1 == NULL) {
            HISI_PRINT_ERROR("p73_receiveChainedFrame 1-KMALLOC FAILED!!!\n");
            return NULL;
        }

        memset(apduBuffer1, 0, p73_apduBufferidx + respData->len);
        memcpy(apduBuffer1, apduBuffer, p73_apduBufferidx);

        // append the received data to the apduBuffer memory

        memcpy((apduBuffer1 + p73_apduBufferidx), respData->data, respData->len);

        SRE_MemFree(0, apduBuffer);
        //add
        apduBuffer = apduBuffer1;
        apduBuffer1 = NULL;
    } else {
        memcpy(apduBuffer + p73_apduBufferidx, respData->data, respData->len);
    }


    //update the index to next free slot
    p73_apduBufferidx += respData->len;

    if (NULL != respData && NULL != respData->data) {
        SRE_MemFree(0, respData->data);
        SRE_MemFree(0, respData);
    }

    // return the entire received apdu
    apdbuff = (respData_t *)SRE_MemAlloc(0, 0, sizeof(respData_t));
    if (apdbuff == NULL) {
        HISI_PRINT_ERROR("p73_receiveChainedFrame 2-KMALLOC FAILED!!!\n");
        return NULL;
    }

    apdbuff->data = (unsigned char *)SRE_MemAlloc(0, 0, p73_apduBufferidx);
    if (apdbuff->data == NULL) {
        HISI_PRINT_ERROR("p73_receiveChainedFrame 3-KMALLOC FAILED!!!\n");
        SRE_MemFree(0, apdbuff);
        return NULL;
    }

    memcpy(apdbuff->data, apduBuffer, p73_apduBufferidx);
    apdbuff->len = p73_apduBufferidx;
    SRE_MemFree(0, apduBuffer);
    apduBuffer = NULL;
    HISI_PRINT_DEBUG("p61 p73_receiveChainedFrame -Exit\n");
    return apdbuff;
}
/**
    * This function is used to send an acknowledge for an received I frame
    * in chaining mode.
    *
    */
void p73_sendAcknowledge(void)
{
    unsigned char ack[4];
    int ret;
    HISI_PRINT_DEBUG("p73_sendAcknowledge - Enter\n");

    // prepare the acknowledge and send it

    ack[0] = 0x00;
    ack[1] = (P73_PH_SCAL_T1_R_BLOCK | (seqCounterCard << 4));
    ack[2] = 0x00;
    ack[3] = p73_helperComputeLRC(ack, 0, sizeof(ack) / sizeof(ack[0]) - 2);

    ret = p73_send((unsigned char **)&ack, P73_C_TRANSMIT_NORMAL_SPI_OPERATION, sizeof(ack) / sizeof(ack[0]));
    if (ret == -1) {
        HISI_PRINT_ERROR("p73_sendAcknowledge - Error\n");
    }

    HISI_PRINT_DEBUG("p73_sendAcknowledge - Exit\n");

}


/**
     * This function is used to send a chained frame.
     *
     * @param data
     *            the data to be send
     */
int p73_sendChainedFrame(const char data[], unsigned int len)
{

    int count_status = 0 ;
    unsigned int length = len;
    int offset = 0;
    int ret = 0;
    char *lastDataPackage = NULL;
    char *dataPackage = NULL;
    HISI_PRINT_DEBUG("p73_sendChainedFrame - Enter\n");
    if (len < p73_ifs) {
        HISI_PRINT_DEBUG("no need to p73_sendChainedFrame!\n");
        return -1;
    }
    dataPackage = gDataPackage;
    do {
        HISI_PRINT_DEBUG("p73_sendChainedFrame \n");
        // send a chained frame and receive the acknowledge
        memcpy(&dataPackage[0], &data[offset], p73_ifs);

        count_status = p73_sendFrame(dataPackage, P73_PH_SCAL_T1_CHAINING, p73_ifs);
        if (count_status == 0) {
            HISI_PRINT_ERROR("ERROR1: Failed to send Frame\n");
            return -1;
        }
        p73_receiveAcknowledge();
        /*SRE_DelayUs(300);*/
        SRE_DelayMs(1);
        length = length - p73_ifs;
        offset = offset + p73_ifs;
        ret += count_status;
    } while (length > p73_ifs);

    // send the last frame
    lastDataPackage = gDataPackage;
    memcpy(&lastDataPackage[0], &data[offset], length);

    count_status = p73_sendFrame(lastDataPackage, P73_PH_SCAL_T1_SINGLE_FRAME, length);

    if (count_status == 0)

    {
        HISI_PRINT_ERROR("ERROR2:Failed to send Frame\n");
        return -1;
    }
    HISI_PRINT_DEBUG("p73_sendChainedFrame - Exit\n");
    ret += count_status;
    return ret;
}
/**
     * This function is used to receive an Acknowledge of an I frame
     *
     */
void p73_receiveAcknowledge(void)
{
    respData_t *header = NULL;
    short rPcb = 0;
    short rLen = 0;
    int len = 1;
    unsigned char *cs = NULL;
    HISI_PRINT_DEBUG("p73_receiveAcknowledge - Enter\n");
    cs = gRecvBuff;
    header = (respData_t *) p73_receiveHeader();

    if (header == NULL)
    return;

    rPcb = (header->data[0] & 0xFF);
    rLen = (header->data[1] & 0xFF);
    p73_receiveAndCheckChecksum(rPcb, rLen, cs, len);
    HISI_PRINT_DEBUG("p73_receiveAcknowledge - Exit\n");
}

/**
 * This function is used to receive the header of the next T=1 frame.
 * If no data is available the function polls the data line as long as it receives the
 * start of the header and then receives the entire header.
 *
 */
respData_t *p73_receiveHeader(void)
{
    int count_status = 0;
    //unsigned char *ready=NULL;
    respData_t *header = NULL;
    int len = 1, times = 3000;
    HISI_PRINT_DEBUG("p73_receiveHeader - Enter\n");
    header = gStRecvData;
    header->data = gRecvBuff;
    header->len = P73_PH_SCAL_T1_HEADER_SIZE_NO_NAD;
    count_status = p73_receive(&gRecvBuff, len, P73_C_TRANSMIT_NO_STOP_CONDITION);
    HISI_PRINT_DEBUG("count_status = %d, sof is :0x%x\n", count_status, gRecvBuff[0]);

    // check if we received ready
    while ((count_status == -1 || gRecvBuff[0] != p73_sof) && times--) {
        HISI_PRINT_DEBUG("SOF not found\n");
        // receive one byte and keep SS line low
        count_status = p73_receive(&gRecvBuff, len, P73_C_TRANSMIT_NO_STOP_CONDITION | P73_C_TRANSMIT_NO_START_CONDITION);
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
    count_status = p73_receive(&(header->data), header->len , P73_C_TRANSMIT_NO_STOP_CONDITION | P73_C_TRANSMIT_NO_START_CONDITION);
    if (count_status == -1) {
        HISI_PRINT_ERROR("ERROR:Failed to receive data from device\n");
        return NULL;
    }
    HISI_PRINT_DEBUG("p73_receiveHeader -Exit\n");

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
void p73_receiveAndCheckChecksum(short rPcb, short rLen, unsigned char data[], int dataLength)
{
    int lrc = rPcb ^ rLen;
    int receivedCs = 0;
    int expectedCs = 0;
    HISI_PRINT_DEBUG("p73_receiveAndCheckChecksum -Enter\n");

    dataLength = dataLength - p73_csSize;

    // compute the expected CS

    expectedCs = 0x5A ^ lrc ^ p73_helperComputeLRC(data, 0, dataLength);

    // receive the T=1 CS
    p73_receive(&checksum, p73_csSize, P73_C_TRANSMIT_NO_START_CONDITION);

    receivedCs = checksum[0];

    // compare the chechsums
    if (expectedCs != receivedCs) {
        HISI_PRINT_DEBUG("expectedCs =%d, receivedCs =%d, Checksum error \n", expectedCs, receivedCs);
    }

    HISI_PRINT_DEBUG("p73_receiveAndCheckChecksum -Exit\n");
}
/**
     * Basic send function which directly calls the spi bird wrapper function
     *
     * @param data
     *            the data to be send
     *
     */
int p73_send(unsigned char **data, unsigned char mode, int len)
{
    int count = 0;
    (void)mode;
    HISI_PRINT_DEBUG("p73_send - Enter len=%d, mode = 0x%x \n", len, mode);

    // call to the spi bird wrapper
    count = p61_dev_write((char *)*data, len);

    if (count == 0) {
        HISI_PRINT_ERROR("ERROR:Failed to send data to device\n");
        return -1;
    }
    return count;
}

int p73_receive(unsigned char **data, int len, unsigned char mode)
{
    static int count_status;
    (void)mode;
    HISI_PRINT_DEBUG("receive -Enter mode = 0x%x \n", mode);
    count_status = p61_dev_read((char *)*data, len);
    if (count_status <= 0) {
        HISI_PRINT_ERROR("ERROR:Failed to receive data from device\n");
        return -1;
    }

    HISI_PRINT_DEBUG("receive -Exit count=%d\n", count_status);

    return count_status;

}

int p61_dev_write(const char *buf, int count)
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
    u32 p61_spi_bus_addr = (u32)p73_spi_bus_addr;

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

int p61_dev_read(char  *buf, int count)
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
    u32 p61_spi_bus_addr = (u32)p73_spi_bus_addr;

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
int p73_sendFrame(const char data[], unsigned char mode, unsigned int count)
{
    int count_status = 0;
    int len = count + p73_headerSize + p73_csSize;
    unsigned char *frame = NULL;
    HISI_PRINT_DEBUG("p73_sendFrame - Enter\n");
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

    frame[count + p73_headerSize] = (unsigned char)p73_helperComputeLRC(frame, 0, count + p73_headerSize - 1);
    lastFrame = frame;
    lastFrameLen = len;
    count_status = p73_send(&frame, P73_C_TRANSMIT_NORMAL_SPI_OPERATION, len);

    if (count_status == 0) {
        HISI_PRINT_ERROR("ERROR:Failed to send device\n");
        return -1;
    }

    HISI_PRINT_DEBUG("p73_sendFrame ret = %d - Exit\n", count_status);
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
unsigned char p73_helperComputeLRC(unsigned char data[], int offset, int length)
{
    int LRC = 0x5A;
    int i = 0;
    HISI_PRINT_DEBUG("p73_helperComputeLRC - Enter\n");
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
void p73_init(void)
{
    HISI_PRINT_DEBUG("p73_init - Enter\n");
    apduBuffer = (unsigned char *) SRE_MemAlloc(0, 0, p73_apduBufferlen);
    if (apduBuffer == NULL) {
        HISI_PRINT_ERROR("p73_init - FAILED TO ALLOCATE MEMORYS \n");
        return;
    }

    memset(apduBuffer, 0, p73_apduBufferlen);

    p73_apduBufferidx = 0;
    seqCounterCard = 0;
    seqCounterTerm = 1;

    HISI_PRINT_DEBUG("p73_init - Exit\n");
}
void p73_open(void)
{
    HISI_PRINT_INFO("p73_open\n");
    p73_alloc_mem();
}

void p73_close(void)
{
    HISI_PRINT_INFO("p73_close\n");
    p73_free_mem();
}

void p73_alloc_mem(void)
{
    gRecvBuff = (unsigned char *)SRE_MemAlloc(0, 0, MAX_FRAME_SIZE);
    gStRecvData = (respData_t *)SRE_MemAlloc(0, 0, sizeof(respData_t));
    checksum = (unsigned char *)SRE_MemAlloc(0, 0, p73_csSize);
    gSendframe = (unsigned char *)SRE_MemAlloc(0, 0, MAX_FRAME_SIZE);
    gDataPackage = (char *)SRE_MemAlloc(0, 0, MAX_FRAME_SIZE);
}
void p73_free_mem(void)
{
    SRE_MemFree(0, gRecvBuff);
    SRE_MemFree(0, gStRecvData);
    SRE_MemFree(0, checksum);
    SRE_MemFree(0, gSendframe);
    SRE_MemFree(0, gDataPackage);
}

int p73_scard_release_cb(void *data)
{
    if(data != NULL){
       HISI_PRINT_INFO("%s: enter \n", __func__);
    }
    return p73_scard_disconnect(0);
}

int p73_scard_get_ese_type(void)
{
    /* init ese config if first run */
    if (NOT_READY == ese_init) {
        p73_load_config();
    }

    if (p73_nfc_ese_num == 2)
    {
        return 2;
    }
    else
    {
        /*p61*/
        if (p73_nfc_ese_type == 1)
        {
            return 1;
        }
        /*hisee*/
        else
        {
            return 0;
        }
    }
}

