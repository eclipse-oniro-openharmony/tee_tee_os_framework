#include <stddef.h>
#include <errno.h>
#include "spi.h"
#include "tee_log.h"
#include <sre_sys.h>
#include <memory.h>
#include "sre_task.h"
#include "securec.h"
#include "sre_syscalls_id_ext.h"
#include <hmdrv_stub.h> // hack for `HANDLE_SYSCALL`
#include "p73.h"
#include "spi_common.h"

#define P73_RETURN_OK 0
#define P73_RETURN_ERROR (-1)
#define ESE_RET_SUCCESS 0
#define ESE_RET_FAIL (-1)

void p73_load_config(void)
{
    return;
}

int p61_dev_write(const char *buf, int count)
{
    int ret = P73_RETURN_ERROR;
    struct spi_transaction_info write_data;

    write_data.reg_addr = NULL;
    write_data.reg_len = 0;
    write_data.buf_addr = buf;
    write_data.buf_len = count;

    if (NULL == buf) {
        tloge("Null Pointer when t1_dev_write!\n");
        return ret;
    }
    ret = ese_driver_spi_full_duplex(&write_data, NULL);
    if (ret != ESE_RET_SUCCESS) {
        return ret;
    }
    return count;
}

int p61_dev_read(char  *buf, int count)
{
    int ret = P73_RETURN_ERROR;
    struct spi_transaction_info write_data;
    struct spi_transaction_info read_data;

    write_data.reg_addr = NULL;
    write_data.reg_len = 0;
    write_data.buf_addr = NULL;
    write_data.buf_len = 0;
    read_data.reg_addr = NULL;
    read_data.reg_len = 0;
    read_data.buf_addr = buf;
    read_data.buf_len = count;
    if (NULL == buf) {
        tloge("Null Pointer when t1_dev_read!\n");
        return ret;
    }
    ret = ese_driver_spi_full_duplex(&write_data, &read_data);
    if (ret != ESE_RET_SUCCESS) {
        return ret;
    }
    return count;
}
