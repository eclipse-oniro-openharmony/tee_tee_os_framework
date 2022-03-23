/*
* Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
* Description: common interface file
* Author: g00466914
* Create: 2019-12-05
* Notes: this file's api is for all TP modules platform wrapper interface
*/
#include "self_adapt_supplier.h"

#define afe_tui_fun_wrapper(key) key##_goodix
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_jennifer_snps
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_b183_nova
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_cindy_snps
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_20x_snps
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper
#define afe_tui_fun_wrapper(key) key##_b20x_goodix
#include "thp_afe_supplier.h"
#undef afe_tui_fun_wrapper

struct_supplier(goodix);
struct_supplier(jennifer_snps);
struct_supplier(b183_nova);
struct_supplier(cindy_snps);
struct_supplier(20x_snps);
struct_supplier(b20x_goodix);

thp_afe_api *g_afe_api_type[] = {
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
	&thp_afe_api_goodix,
	&thp_afe_api_jennifer_snps,
	&thp_afe_api_jennifer_snps,
	&thp_afe_api_jennifer_snps,
	&thp_afe_api_jennifer_snps,
	&thp_afe_api_goodix,
	&thp_afe_api_b183_nova,
	&thp_afe_api_b183_nova,
	&thp_afe_api_b183_nova,
	&thp_afe_api_cindy_snps,
	&thp_afe_api_20x_snps,
	&thp_afe_api_20x_snps,
	&thp_afe_api_20x_snps,
	&thp_afe_api_20x_snps,
	&thp_afe_api_20x_snps,
	&thp_afe_api_20x_snps,
	&thp_afe_api_20x_snps,
	&thp_afe_api_20x_snps,
	&thp_afe_api_20x_snps,
	&thp_afe_api_20x_snps,
	&thp_afe_api_20x_snps,
	&thp_afe_api_b20x_goodix,
	&thp_afe_api_b20x_goodix,
	&thp_afe_api_b20x_goodix,
	&thp_afe_api_b20x_goodix,
	&thp_afe_api_b20x_goodix,
	&thp_afe_api_b20x_goodix,
	&thp_afe_api_b20x_goodix,
	&thp_afe_api_b20x_goodix,
	&thp_afe_api_b20x_goodix,
	&thp_afe_api_b20x_goodix,
	&thp_afe_api_b20x_goodix,
	&thp_afe_api_b20x_goodix,
	&thp_afe_api_b20x_goodix,
	NULL
};

char *g_projectid_text[] = {
	"B179AD1500", /* bmh goodix 9896S EDO */
	"B179930900", /* bmh goodix 9896S */
	"B196931300", /* jer goodix 9896S */
	"B196931301",
	"B196931302",
	"B196931310",
	"B196931311",
	"B196931312",
	"B196931320",
	"B196931321",
	"B196932900",
	"B196932910",
	"B196932920",
	"B196922900", /* jer syna S3909 */
	"B196922910",
	"B196922920",
	"B19X922921",
	"B179930901", /* jef goodix 9896S */
	"B183771100", /* cindy tm + novateck */
	"B183772700", /* cindy tcl + novateck */
	"B183771300", /* cindy boe + novateck */
	"B183691300", /* cindy boe + syna */
	"B205921300",
	"B205921310",
	"B205922900",
	"B205922910",
	"B205922911",
	"B206921300",
	"B206921310",
	"B206922900",
	"B206922910",
	"B206921100",
	"B206921110",
	"B2059S1300",
	"B2059S2900",
	"B2059S2910",
	"B2059S1301",
	"B2059S2911",
	"B2069S1300",
	"B2069S2900",
	"B2069S2910",
	"B2069S1301",
	"B2069S1311",
	"B2069S2901",
	"B2069S2911",
	"B2069S1310",
	"N/A" /* NA AFE THP */
};
