#include <sre_typedef.h>
#include <register_ops.h> // writel
#include <drv_module.h>
#include "tee_log.h"
#include <tzpc.h>
#if (TRUSTEDCORE_PLATFORM_CHOOSE == WITH_HIGENERIC_PLATFORM)
#include "./../../kirin/tzpc/tzpc_cfg.h"
#endif
/* bit value in reg is 0(low) means secure status */
static BOOL high_is_secure = FALSE;

/* define the offeset of the stat/set/clr registeris */
#define TZPC_DECPROTXSTAT(i)    (UINTPTR)(0x800 + (i) * 0x0c)
#define TZPC_DECPROTXSET(i)     (UINTPTR)(0x804 + (i) * 0x0c)
#define TZPC_DECPROTXCLR(i)     (UINTPTR)(0x808 + (i) * 0x0c)

#define ERROR (-1)
#define OK      (0)
extern void uart_printf_func(const char *fmt, ...);


/**********************************************************************
* tzpc functions
*
***********************************************************************/
/*
 * @tzpc_cfg_bit - description: -- config the ip bit
 * @unit_no     :
 * @bit_idx     :
 * @sec_status  :
 * @Date: 2013/10/16
 *
 */
static int tzpc_get_bit(unsigned int tbl_no, unsigned int unit_no, unsigned int bit_idx)
{
	UINT32 reg_value;
	UINTPTR stat_reg_addr = TZPC_BASE_ADDR + TZPC_DECPROTXSTAT(unit_no);
	UINT32 bit_value;
	UINTPTR base_addr;
	/* 1 indicating non-security ; 0 indicating security*/

	if (unit_no >= TZPC_MAX_UNIT || bit_idx >= 32 || tbl_no >= TZPC_TABLE_MAX) {
		tloge("[%s_%d]: tbl_no 0x%x unit_no 0x%x or bit_idx 0x%x is invalid\n", __func__, __LINE__, tbl_no, unit_no, bit_idx);
		return ERROR;
	}

	if (TZPC_TABLE_AO == tbl_no) {
		base_addr = TZPC_AO_BASE_ADDR;
	} else {
		base_addr = TZPC_BASE_ADDR;
	}
	stat_reg_addr = base_addr + TZPC_DECPROTXSTAT(unit_no);

	reg_value = readl(stat_reg_addr);

	bit_value = (unsigned int)(!!(reg_value & ((unsigned int)1 << (unsigned int)bit_idx)));
	if (high_is_secure  == bit_value) {
		return TZPC_SEC;
	} else {
		return TZPC_UNSEC;
	}

}

/**********************************************************************
* tzpc functions
*
***********************************************************************/
/*
 * @tzpc_cfg_bit - description: -- config the ip bit
 * @unit_no     :
 * @bit_idx     :
 * @sec_status  :
 * @Date: 2013/10/16
 *
 */
static int tzpc_cfg_bit(unsigned int tbl_no, unsigned int unit_no, unsigned int bit_idx, unsigned int sec_status)
{
	UINT32 reg_value;
	UINTPTR stat_reg_addr;
	UINTPTR clr_reg_addr;
	UINTPTR set_reg_addr;
	UINTPTR secure_addr;
	UINTPTR unsecure_addr;
	UINTPTR base_addr;

	/* 1 indicating non-security ; 0 indicating security*/
	if (tbl_no >= TZPC_TABLE_MAX || bit_idx >= 32) {
		tloge("[%s_%d]: table_no 0x%x or bit_idx 0x%x is invalid\n", __func__, __LINE__, tbl_no, bit_idx);
		return ERROR;
	}
	if(unit_no >= TZPC_MAX_UNIT) {
		tloge("[%s_%d]: table_no 0x%x unit_no 0x%x is invalid\n", __func__, __LINE__, tbl_no, unit_no);
		return ERROR;
	}

	if (TZPC_TABLE_AO == tbl_no) {
		base_addr = TZPC_AO_BASE_ADDR;
	} else {
		base_addr = TZPC_BASE_ADDR;
	}

	stat_reg_addr = base_addr + TZPC_DECPROTXSTAT(unit_no);
	clr_reg_addr = base_addr + TZPC_DECPROTXCLR(unit_no);
	set_reg_addr = base_addr + TZPC_DECPROTXSET(unit_no);
	secure_addr = high_is_secure?set_reg_addr:clr_reg_addr;
	unsecure_addr = high_is_secure?clr_reg_addr:set_reg_addr;

	reg_value = readl(stat_reg_addr);

	if (sec_status == TZPC_SEC) {
		if (high_is_secure ^ (reg_value & (1U << bit_idx))) {
			/*clr the bit*/
			writel(1U << bit_idx, secure_addr);
		}
	} else {
		if (high_is_secure ^ (unsigned int)(!(reg_value & (1U << bit_idx)))) {
			/*set the bit*/
			writel(1U << bit_idx, unsecure_addr);
		}
	}

	return OK;
}

static int _tzpc_ip_pos_search(unsigned int ip_num, unsigned int *ppos)
{
	TZPC_BIT_DEF *tzpc_bit_def = &tzpc_tbl[0];
	unsigned int i, pos, count = sizeof(tzpc_tbl) / sizeof(tzpc_tbl[0]);

	if ((ip_num < count) && (tzpc_bit_def[ip_num].ip_idx == ip_num)) {
		pos = ip_num;
	} else {
		/*search the ip_num in tzpc_tbl*/
		for (i = 0 ; i < count; i++) {
			if (tzpc_bit_def[i].ip_idx == ip_num) {
				break;
			}
		}

		if (i >= count) {
			/*can't find the ip_num in table*/
			tloge("[%s_%d]: can't find ip_num 0x%x \n", __func__, __LINE__, ip_num);
			return ERROR;
		}

		pos = i;
	}

	*ppos = pos;
	return OK;
}

/*
 * @tzpc_cfg - description: -- config ip
 * @ip_num      :
 * @sec_status  :
 * @Date: 2013/10/16
 *
 */
int _tzpc_cfg_ip(unsigned int ip_num, unsigned int sec_status)
{
	TZPC_BIT_DEF *tzpc_bit_def = &tzpc_tbl[0];
	unsigned int pos = 0;

	if (ip_num >= TZPC_IP_NUM_MAX || sec_status >= TZPC_ATTR_MAX) {
		tloge("[%s_%d]: ip_num 0x%x is invalid\n", __func__, __LINE__, ip_num);
		return ERROR;
	}

	if (0 != _tzpc_ip_pos_search(ip_num, &pos)) {
		tloge("[%s_%d]: ip_num 0x%x pos search fail\n", __func__, __LINE__, ip_num);
		return ERROR;
	}

	return tzpc_cfg_bit(tzpc_bit_def[pos].tbl_no, tzpc_bit_def[pos].unit_no, tzpc_bit_def[pos].bit_no, sec_status);
}

int _tzpc_get_ip(unsigned int ip_num)
{
	TZPC_BIT_DEF *tzpc_bit_def = &tzpc_tbl[0];
	unsigned int pos = 0;

	if (ip_num >= TZPC_IP_NUM_MAX) {
		tloge("[%s_%d]: ip_num 0x%x is invalid\n", __func__, __LINE__, ip_num);
		return ERROR;
	}

	if (0 != _tzpc_ip_pos_search(ip_num, &pos)) {
		tloge("[%s_%d]: ip_num 0x%x pos search fail\n", __func__, __LINE__, ip_num);
		return ERROR;
	}

	return tzpc_get_bit(tzpc_bit_def[pos].tbl_no, tzpc_bit_def[pos].unit_no, tzpc_bit_def[pos].bit_no);
}

int tzpc_cfg(unsigned int ip_num, unsigned int sec_status)
{
	if (ip_num >= sizeof(tzpc_link) / sizeof(unsigned int)
	    || tzpc_link[ip_num] == INVALID_ID) {
		tloge("[%s_%d]: can't find ip_num 0x%x \n", __func__, __LINE__, ip_num);
		return ERROR;
	}
	return _tzpc_cfg_ip((unsigned int)tzpc_link[ip_num], sec_status);
}

int tzpc_get(unsigned int ip_num)
{
	if (ip_num >= sizeof(tzpc_link) / sizeof(unsigned int)
	    || tzpc_link[ip_num] == INVALID_ID) {
		tloge("[%s_%d]: can't find ip_num 0x%x \n", __func__, __LINE__, ip_num);
		return ERROR;
	}
	return _tzpc_get_ip((unsigned int)tzpc_link[ip_num]);
}


int tzpc_testcase1(void)
{
	uart_printf_func("tzpc_testcase\n");
	unsigned int test_ip = TZ_I2C0;
	char name[] = "TZ_I2C0";
	int raw_status, status;
	int ret;

	status = tzpc_get(test_ip);
	raw_status = status;
	uart_printf_func("get %s status is %d\n", name, status);
	ret = tzpc_cfg(test_ip, (unsigned int)(!status));
	uart_printf_func("set %s to %d ret %d\n", name, (unsigned int)(!status), ret);
	status = tzpc_get(test_ip);
	uart_printf_func("get %s status is %d\n", name, status);
	ret = tzpc_cfg(test_ip, (unsigned int)raw_status);
	uart_printf_func("set %s back to raw_status %d ret %d\n", name, raw_status, ret);
	status = tzpc_get(test_ip);
	uart_printf_func("get %s status is %d\n", name, status);

	return OK;
}

