/*
* Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
* Description: common interface file
* Author: l00492120 & c00414356
* Create: 2019-10-23
* Notes: this file's api is for all TP modules platform wrapper interface
*/
#include "self_adapt_supplier.h"

#define afe_tui_fun_wrapper(key) key##_waltz_snps
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_b166_nova
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_oxford_snps
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_b165_nova
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_edinburgh_snps
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_goodix
#include "thp_afe_supplier.h"

struct_supplier(waltz_snps);
struct_supplier(b166_nova);
struct_supplier(oxford_snps);
struct_supplier(b165_nova);
struct_supplier(edinburgh_snps);
struct_supplier(goodix);

thp_afe_api* g_afe_api_type[] = {
	&thp_afe_api_b166_nova,
	&thp_afe_api_b166_nova,
	&thp_afe_api_b166_nova,
	&thp_afe_api_b166_nova,
	&thp_afe_api_waltz_snps,
	&thp_afe_api_waltz_snps,
	&thp_afe_api_waltz_snps,
	&thp_afe_api_b165_nova,
	&thp_afe_api_b165_nova,
	&thp_afe_api_b165_nova,
	&thp_afe_api_b165_nova,
	&thp_afe_api_oxford_snps,
	&thp_afe_api_oxford_snps,
	&thp_afe_api_oxford_snps,
	&thp_afe_api_edinburgh_snps,
	&thp_afe_api_edinburgh_snps,
	&thp_afe_api_edinburgh_snps,
	&thp_afe_api_edinburgh_snps,
	&thp_afe_api_edinburgh_snps,
	&thp_afe_api_goodix,
	&thp_afe_api_goodix,
	&thp_afe_api_goodix,
	&thp_afe_api_goodix,
	&thp_afe_api_goodix,
	&thp_afe_api_goodix,
	&thp_afe_api_goodix,
	&thp_afe_api_goodix,
	&thp_afe_api_goodix,
	&thp_afe_api_goodix,
	&thp_afe_api_goodix,
	&thp_afe_api_goodix,
    NULL
};

char* g_projectid_text[] = {
	"B166771300", /* waltz boe + novateck */
	"B166771100", /* waltz tm + novateck */
	"B166771700", /* waltz auo + novateck */
	"B166772700", /* waltz tcl + novateck */
	"B166961100", /* waltz tm + syna */
	"B166962700", /* waltz tcl + syna */
	"B166961300", /* waltz boe + syna */
	"B165771300", /* oxford boe + novateck */
	"B165771100", /* oxford tm + novateck */
	"B165771700", /* oxford auo + novateck */
	"B165772700", /* oxford tcl + novateck */
	"B165961100", /* oxford tm + syna */
	"B165962700", /* oxford tcl + syna */
	"B165961300", /* oxford boe + syna */
	"B177922900", /* edin Visionox + syna */
	"B177922910", /* edin Visionox + syna */
	"B177922920", /* edin Visionox + syna */
	"B177922930", /* edin Visionox + syna */
	"B177922940", /* edin Visionox + syna */
	"B177931300", /* edin boe + goodix */
	"B177931310", /* edin boe + goodix */
	"B177931320", /* edin boe + goodix */
	"B177931330", /* edin boe + goodix */
	"B177931340", /* edin boe + goodix */
	"B177931303", /* edin boe + goodix */
	"B177931313", /* edin boe + goodix */
	"B177932900", /* edin Visionox + goodix */
	"B177932910", /* edin Visionox + goodix */
	"B177932920", /* edin Visionox + goodix */
	"B17X931330", /* edin boe + goodix 90HZ */
	"B17X931340", /* edin boe + goodix 90HZ */
	"N/A" /* NA AFE THP */
};
