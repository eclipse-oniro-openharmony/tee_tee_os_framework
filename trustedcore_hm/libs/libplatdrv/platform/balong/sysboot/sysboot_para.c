/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 */
#include <bsp_modem_product_config.h>
#include <drv_module.h>
#include <sre_typedef.h>
#include <bsp_shared_ddr.h>
#include <bsp_sysboot.h>
#include <string.h>
#include <securec.h>

#ifdef CONFIG_SYSBOOT_PARA
struct sysboot_para_info {
    char *vir_addr;
    phy_addr_t phy_addr;
    u32 buf_max_size;
};

struct sysboot_args_info {
    int equal_pos;
    int in_quote;
    int equal_pos_modified;
    int quote_pos_modified;
    int space_pos_modified;
};

enum {
    SYSBOOT_PARA_ERROR = -2,
    SYSBOOT_PARA_NO_MEM = -1,
    SYSBOOT_PARA_OK = 0,
};

struct sysboot_para_info g_sysboot_para;

extern struct sysboot_parse_para_info g_sysboot_parse_para_info[];


static struct sysboot_para_info *get_para_info(void)
{
    return &g_sysboot_para;
}

static inline int is_space(char c)
{
    return (c == ' ') || (c == '\t') || (c == '\r') || (c == '\n');
}

int bsp_sysboot_print_para(void)
{
    struct sysboot_para_info *para = get_para_info();

    tloge("secure_os boot para:%s\n", para->vir_addr);
    return SYSBOOT_PARA_OK;
}

static char * sysboot_skip_spaces(const char *str)
{
    while (is_space(*str)) {
        ++str;
    }
    return (char *)str;
}

static void sysboot_do_early_para(char *name, char *val)
{
    unsigned int i;
    unsigned int para_info_size = sizeof(g_sysboot_parse_para_info) / sizeof(struct sysboot_parse_para_info);
    struct sysboot_parse_para_info *p = NULL;

    for (i = 0; i < para_info_size; i++) {
        p = &(g_sysboot_parse_para_info[i]);
        if (strcmp(p->name, name) == 0) {
            if (p->init_fun != NULL) {
                p->result = p->init_fun(val);
                break;
            }
        }
    }
}

static void sysboot_args_restore(char *args, struct sysboot_args_info *info, int pos, char space_value)
{
    if (info->equal_pos_modified) {
        args[info->equal_pos] = '=';
    }

    if (info->quote_pos_modified) {
        args[pos - 1] = '"';
    }

    if (info->space_pos_modified) {
        args[pos] = space_value;
    }
}

char *parse_next_args(char *args)
{
    char *name = NULL;
    char *value = NULL;
    char *next_args = NULL;
    int i;
    char space_value = ' ';
    struct sysboot_args_info info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));

    for (i = 0; args[i] != '\0'; i++) {
        if (is_space(args[i]) && !(info.in_quote)) {
            break;
        }

        if (args[i] == '=') {
            info.equal_pos = i;
        }

        if (args[i] == '"') {
            info.in_quote = !(info.in_quote);
        }
    }

    name = args;
    if (info.equal_pos == 0) {
        value = NULL;
    } else {
        args[info.equal_pos] = '\0';
        info.equal_pos_modified = 1;
        value = args + info.equal_pos + 1;
        if (*value == '"') {
            value = value + 1;
            if (args[i - 1] == '"') {
                args[i - 1] = '\0';
                info.quote_pos_modified = 1;
            }
        }
    }

    if (args[i]) {
        space_value = args[i];
        args[i] = '\0';
        next_args = args + i + 1;
        info.space_pos_modified = 1;
    } else {
        next_args = args + i;
    }

    if (value != NULL) {
        sysboot_do_early_para(name, value);
    }

    sysboot_args_restore(args, &info, i, space_value);

    return sysboot_skip_spaces(next_args);
}

static void sysboot_parse_args(char *paras)
{
    char *args = sysboot_skip_spaces(paras);

    while (*args) {
        args = parse_next_args(args);
    }
}

void sysboot_parse_boot_para(void)
{
    struct sysboot_para_info *para = get_para_info();

    sysboot_parse_args(para->vir_addr);
}

static int sysboot_get_para_from_shm(void)
{
    struct sysboot_para_info *para = get_para_info();

    para->vir_addr = (char *)bsp_mem_share_get("seshm_secure_os_para", &(para->phy_addr), &(para->buf_max_size), SHM_SEC);
    if (para->vir_addr == NULL) {
        tloge("get para by shm err\n");
        return SYSBOOT_PARA_ERROR;
    }

    return SYSBOOT_PARA_OK;
}

#ifdef CONFIG_SYSBOOT_PARA_DEBUG
int parse_secureos_debug(const char *p)
{
    tloge("secureos_boot_para_test=%s\n",p);
    return SYSBOOT_PARA_OK;
}
#endif
#endif /* CONFIG_SYSBOOT_PARA */

int bsp_sysboot_para_init(void)
{
    int ret;

    ret = sysboot_get_para_from_shm();
    if (ret) {
        return ret;
    }

    sysboot_parse_boot_para();
    bsp_sysboot_print_para();
    tloge("para init ok\n");
    return ret;
}

DECLARE_TC_DRV(sysboot_param, 0, 0, 0, 0, bsp_sysboot_para_init, NULL, NULL, NULL, NULL);

