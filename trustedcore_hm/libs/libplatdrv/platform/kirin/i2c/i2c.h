#ifndef ___I2C_H_
#define ___I2C_H_

#include <hisi_boot.h>

/*   Read/Write interface:
 *
 *   chip_addr:         I2C chip address
 *   buf:               Where to read/write the data,
 *                      reg should be writen in buf[0]
 *   len:               How many bytes to read/write
 *
 *   Returns:           0 on success, not 0 on failure
 */
int hisi_i2c_read(const u32 chip_addr, u8 *buf, u32 len, const u32 slave_addr);
int hisi_i2c_read_directly(
	const u32 chip_addr, u8 *buf, u32 len, const u32 slave_addr);
int hisi_i2c_read_reg16(
	const u32 chip_addr, u8 *buf, u32 len, const u32 slave_addr);
int hisi_i2c_write(const u32 chip_addr, u8 *buf, u32 len, const u32 slave_addr);

extern void uart_printf_func(const char *fmt, ...);

#endif
