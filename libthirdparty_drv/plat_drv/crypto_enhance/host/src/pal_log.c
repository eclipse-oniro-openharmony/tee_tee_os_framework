/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: pal_log function
 * Author: z00293770
 * Create: 2018-08-20
 */

#include <pal_log.h>
#include <common_utils.h>

#ifdef FEATURE_DFT_ENABLE
u32 g_pal_log_trace;
#endif /* FEATURE_DFT_ENABLE */

#ifdef FEATURE_DFT_ENABLE
/*
 * @brief      : set trace control
 * @param[in]  : enable PAL_PAL_TRUE - disable or OTHER - enable
 */
void pal_set_trace(u32 enable)
{
	g_pal_log_trace = enable;
}

/*
 * trace enable or not
 */
u32 pal_get_trace(void)
{
	return g_pal_log_trace;
}

#endif /* FEATURE_DFT_ENABLE */

/*
 * @brief      : dump register or memory data
 * @param[in]  : addr   mem/reg address
 * @param[in]  : length data length
 * @param[in]  : is_reg PAL_TRUE--register format, PAL_FALSE--memory format
 */
void pal_dump(u8 *addr, u32 length, u32 is_reg)
{
	u32 value = 0;
	u32 len = 0;
	u8 *data = addr;
	char tmp_buf[] = { ' ', '\0', '\0', '\0' };

	if (!addr) {
		PAL_PRINTF(PAL_LOG_INFO, "addr is null\n");
		return;
	}
	while (length > len) {
		if ((len & 0xF) == 0) {
			if (is_reg == PAL_TRUE)
				PAL_PRINTF(PAL_LOG_INFO, "\n\t[" PAL_FMT_PTR "]:", INTEGER(addr));
			else
				PAL_PRINTF(PAL_LOG_INFO, "\n\t[%u]:", len);
		}
		if ((addr == data) && ((length - len) >= sizeof(u32))) {
			value = *((u32 *)addr);
			data = (u8 *)&value;
			if (is_reg == PAL_TRUE) {
				value = U32_REV(value);
				PAL_PRINTF(PAL_LOG_INFO, "0x");
			}
		}
		tmp_buf[2] = U8_LSB(*data);      /* 2: u8 low 4bit */
		tmp_buf[2] = TOHEXU(tmp_buf[2]); /* 2: u8 low 4bit to hex */
		tmp_buf[1] = U8_MSB(*data);      /* u8 high 4bit */
		tmp_buf[1] = TOHEXU(tmp_buf[1]); /* u8 high 4bit to hex */

		if (is_reg != PAL_TRUE)  /* 4bytes a group */
			PAL_PRINTF(PAL_LOG_INFO, "%s", tmp_buf);
		else
			PAL_PRINTF(PAL_LOG_INFO, "%s", (tmp_buf + 1));
		data++;
		addr++;
		len++;
		if ((u8 *)(&value + 1) == data) {
			data = addr;
			PAL_PRINTF(PAL_LOG_INFO, " ");
		}
	}
	PAL_PRINTF(PAL_LOG_INFO, "\n");
}

