/****************************************************************************//**
 * @file   hat_entry.c
 * @brief
 * @par    Copyright (c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   2018/08/20
 * @author L00265041
 * @note
 *
********************************************************************************/
#include <pal_libc.h>
#include <pal_timer.h>
#include <common_utils.h>
#include <hieps_agent.h>
#include "hat_entry.h"
#include "hat_framework.h"
#include <eps_ddr_layout_define.h>


/*===============================================================================
 *                               types/macros                                  *
===============================================================================*/
#ifdef errno
#undef errno
#endif

#define HIEPS_AUTOTEST_TIMEOUT (1000 * 1000 * 1000)
typedef enum {
    TEST_PRINT = 0,
    TEST_HIEPS_BSP,
    TEST_HIEPS_OTHER,
    TEST_BUTTOM
} hieps_test_type;

typedef enum {
	TYPE_SCE,
	TYPE_ECC,
	TYPE_RSA,
	TYPE_SM2,
	TYPE_TRNG,
	TYPE_RSA_CRT,
	TYPE_RSA_CRT2STD,
	TYPE_RSA_BASIC_CALC,
	TYPE_HIEPS_AUTOTEST,
} ENGINE_TYPE;

typedef struct {
    unsigned testcase_size;
    unsigned test_type;
    unsigned testcase_type;
    unsigned test_result;
    unsigned errno;
    unsigned cost_time;
    u8 test_data[0];
} se_test_img_struct;

typedef struct {
    int flag;
    int result_addr;
    int result_size;
    int img[0];
} se_test_transfer_struct;

typedef struct hat_plat_info_stru {
	u8 *plat;
	u8 *chip_type;
} hat_plat_info_s;


/*===========================================================================
 *                      functions                                          *
===========================================================================*/
u32 hat_is_fpga(void)
{
	return 0;
}

u32 hat_get_plat_info(hat_plat_info_s *plat_info_s)
{
#define HAT_NAME_LEN_MAX 16
#ifndef FEATURE_PLATFORM_NAME
#define FEATURE_PLATFORM_NAME "default"
#endif /* FEATURE_PLATFORM_NAME */
#ifndef FEATURE_CHIP_TYPE
#define FEATURE_CHIP_TYPE "default"
#endif /* FEATURE_CHIP_TYPE */
	const char *plat = FEATURE_PLATFORM_NAME;   /*lint !e40*/
	const char *chip_type = FEATURE_CHIP_TYPE; /*lint !e40*/
	u32 len;
	if ((NULL == plat_info_s)
		|| (NULL == plat_info_s->plat)
		|| (NULL == plat_info_s->chip_type)) {
		PAL_ERROR("pointer is NULL\n");
		return (u32)SE_RET_ERR;
	}
	len = pal_strnlen(plat, HAT_NAME_LEN_MAX - 1);
	if (memcpy_s(plat_info_s->plat, len, plat, len) != EOK) {
		PAL_ERROR("memcpy_s err0\n");
		return (u32)SE_RET_ERR;
	}
	plat_info_s->plat[len] = '\0';
	len = pal_strnlen(chip_type, HAT_NAME_LEN_MAX - 1);
	if (memcpy_s(plat_info_s->chip_type, len, chip_type, len) != EOK) {
		PAL_ERROR("memcpy_s err1\n");
		return (u32)SE_RET_ERR;
	}
	plat_info_s->chip_type[len] = '\0';

	return SE_RET_OK;
}

STATIC_INLINE int autotest_main(void *data, unsigned int size)
{
	se_test_img_struct *img = (se_test_img_struct *)data;
	se_ntlv_struct *frame = NULL;
	int ret;
	u32 data_size;
	u32 time;

	data_size = img->testcase_size;
	if (size < img->testcase_size) {
		HAT_ERROR("Fatal error: left size %d, but case size = %d!!\n", size, img->testcase_size);
		return SE_RET_ERR;
	}

	time = pal_timer_value();
	img->cost_time = 0;
	switch (img->testcase_type) {
		case TYPE_HIEPS_AUTOTEST:
			ret = autotest_framework_case(img->test_data, (size - sizeof(se_test_img_struct)), &img->cost_time);
			frame = ((se_ntlv_struct *)img->test_data);
			img->testcase_size = sizeof(se_test_img_struct) + sizeof(se_ntlv_struct) + frame->tag_length;
			break;
		default:
			HAT_ERROR("Fatal error: unknow testcase_type = %d!!\n", img->testcase_type);
			return SE_RET_ERR;
	}
	if (0 == img->cost_time) {
		img->cost_time = (u32)pal_tick2us(PAL_TIMER_INTERVAL(pal_timer_value(), time));
	}
	if (ret == SE_RET_OK) {
		img->test_result = RET_OK;
	} else {
		img->test_result = RET_ERR;
	}
	/* mult testcase, now input datasize must equal to output datasize!! */
	img->errno = (u32)ret;

	HAT_INFO("req_size = %d & rsp_size = %d, cost = %dus\n", data_size, img->testcase_size, img->cost_time);
	return SE_RET_OK;
}

int hat_testcase_entry(void *data, unsigned size, unsigned max_len)
{
	u32 begin;
	u32 end;
	int ret = SE_RET_ERR;
	errno_t libc_ret = EINVAL;

	se_test_img_struct *img = (se_test_img_struct *)data;
	u8 *new_data = NULL;

	PAL_CHECK_RETURN((NULL == data) || (size < sizeof(se_test_img_struct)) || (size > max_len), SE_RET_ERR);
	HAT_INFO("test_type = %d, case_type = %d\n", img->test_type, img->testcase_type);
	switch (img->test_type) {
		case TEST_HIEPS_BSP:
			 /* reserved 2k shared ddr for ipc channel, others for data */
			max_len = MIN(max_len, HIEPS_SHARE_DDR_ENG_GENERIC_DATA_SIZE - 2 * 1024);
			new_data = hieps_mem_new(NULL, max_len);
			PAL_CHECK_RETURN((NULL == new_data), SE_RET_ERR);
			img = (se_test_img_struct *)new_data;
			libc_ret = memcpy_s(new_data, max_len, data, size);
			if (EOK != libc_ret) {
				hieps_mem_delete(img);
				PAL_ERROR("libc_ret = "PAL_FMT_PTR"\n",
					   libc_ret);
				return SE_RET_ERR;
			}
			new_data = hieps_mem_convert2hieps(new_data);
			begin = pal_timer_value();
			ret = (int)hieps_run_func(HIEPS_AUTOTEST_TIMEOUT,
							FUNC_AUOTEST_MAIN, FUNC_PARAMS_2, new_data, max_len);
			end = pal_timer_value();
			if (ret == SE_RET_OK) {
				HAT_INFO("hieps test ok, cost = %dus\n", pal_tick2us(PAL_TIMER_INTERVAL(end, begin)));
			} else {
				img->test_result = RET_ERR;
				HAT_ERROR("hieps test fail errno "PAL_FMT_PTR"\n", ret);
			}
			*((u32 *)data) = sizeof(u32) + img->testcase_size;
                        libc_ret = memcpy_s(((u32 *)data + 1), max_len - sizeof(u32), img, img->testcase_size);
			hieps_mem_delete(img);
			PAL_CHECK_RETURN((EOK != libc_ret), SE_RET_ERR);
			break;
		case TEST_HIEPS_OTHER:
			begin = pal_timer_value();
			ret = autotest_main(data, max_len);
			end = pal_timer_value();
			if (ret == SE_RET_OK) {
				HAT_INFO("tee test ok, cost = %dus\n", pal_tick2us(PAL_TIMER_INTERVAL(end, begin)));
			} else {
				HAT_ERROR("tee test fail errno = "PAL_FMT_PTR"\n", ret);
			}
			size = sizeof(u32) + img->testcase_size;
                        libc_ret = memmove_s(((u32 *)data + 1), max_len - sizeof(u32), data, img->testcase_size);
			PAL_CHECK_RETURN((EOK != libc_ret), SE_RET_ERR);
			*((u32 *)data) = size;
			break;
		default:
			HAT_ERROR("test_type=%d fail\n", img->test_type);
			break;
	}
	return ret;
}

