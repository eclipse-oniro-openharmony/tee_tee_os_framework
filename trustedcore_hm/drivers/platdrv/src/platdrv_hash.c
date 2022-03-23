/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: define functions about hash map driver module and syscalls.
 * Create: 2020-06-24
 */
#include "platdrv_hash.h"
#include <string.h>
#include <inttypes.h>
#include <hmlog.h>
#include "drv_module.h"

/* find module by name */
static uintptr_t g_hash_map[DRV_MOUDLE_MAX];
/* the map of syscall id and drv module name */
static struct drv_map_id_info g_hash_map_id[MAP_ID_MAX];
/* name, syscall_list, size ----> get all from name */
static struct module_info g_module_info[DRV_MOUDLE_MAX];

struct tc_drv_desc *g_tc_drvs = NULL;
uint32_t g_tc_drvs_nr;
struct tc_drv_desc *g_tc_drvs_multi = NULL;
uint32_t g_tc_drvs_multi_nr;
struct tc_drv_desc *g_tc_drvs_self_multi = NULL;
uint32_t g_tc_drvs_self_multi_nr;

struct module_info *get_g_module_info(void)
{
    return g_module_info;
}

#define BITS_PER_BYTE    8U
#define BITS_HALF_BYTE   4U
#define HASH_VAR 0x2
static uint32_t get_value_hash(uint16_t value)
{
    return ((((value & 0xf000) >> (BITS_PER_BYTE +  BITS_HALF_BYTE)) / HASH_VAR) * ID_MAX) +
            ((value & 0xf00) >> (BITS_PER_BYTE)) +
            ((value & 0xf0) >> BITS_HALF_BYTE) +
            (value & 0xf);
}

static void hash_map_core(uint32_t key, int32_t i)
{
    int32_t j = 0;
    uint32_t m;
    bool found = false;
    uint32_t hash_key;

    g_hash_map[key] = (uintptr_t)&(g_module_info[i]);
    while (j < g_module_info[i].syscall_num) {
        key = get_value_hash(g_module_info[i].syscall_list[j]);
        hash_key = key;
        while (g_hash_map_id[key].id != 0) {
            key = (key + 1) % MAP_ID_MAX;
            if (key == hash_key) {
                hm_error("g_hash_map_id has been used up\n");
                return;
            }
        }

        g_hash_map_id[key].id = g_module_info[i].syscall_list[j];
        g_hash_map_id[key].name = g_module_info[i].name;

        for (m = 0; m < g_tc_drvs_multi_nr; m++) {
            if (g_module_info[i].name == g_tc_drvs_multi[m].name) {
                g_module_info[i].syscall = g_tc_drvs_multi[m].syscall;
                g_module_info[i].multi_flag = MODULE_MULTI_THREAD_FLAG;
                found = true;
                break;
            }
        }

        for (m = 0; m < g_tc_drvs_self_multi_nr; m++) {
            if (g_module_info[i].name == g_tc_drvs_self_multi[m].name) {
                g_module_info[i].syscall = g_tc_drvs_self_multi[m].syscall;
                g_module_info[i].multi_flag = MODULE_SELF_MULTI_THREAD_FLAG;
                found = true;
                break;
            }
        }

        j++;
    }
    if (found == false)
        hm_error("can not find module name %s\n", g_module_info[i].name);
}

void drv_hash_map(void)
{
    uint32_t i = 0;

    drv_module_init();
    uint32_t drv_module_size = get_drv_module_size();
    g_tc_drvs = (struct tc_drv_desc *)TC_DRV_DESCS_START;
    g_tc_drvs_nr = (TC_DRV_DESCS_END - TC_DRV_DESCS_START) / sizeof(struct tc_drv_desc);

    g_tc_drvs_multi = (struct tc_drv_desc *)TC_DRV_DESCS_MULTI_START;
    g_tc_drvs_multi_nr = (TC_DRV_DESCS_MULTI_END - TC_DRV_DESCS_MULTI_START) / sizeof(struct tc_drv_desc);

    g_tc_drvs_self_multi = (struct tc_drv_desc *)TC_DRV_DESCS_SELF_MULTI_START;
    g_tc_drvs_self_multi_nr = (TC_DRV_DESCS_SELF_MULTI_END -
                              TC_DRV_DESCS_SELF_MULTI_START) / sizeof(struct tc_drv_desc);

    while (i < drv_module_size) {
        int32_t key = g_module_info[i].name[0] - 'a';
        if (key < 0)
            key += ('a' - 'A');
        if (key < 0 || key >= DRV_MOUDLE_MAX)
            hm_panic("[error] the first char of module %s is out of bound, please check!\n", g_module_info[i].name);

        do {
            if (g_hash_map[key] == 0) {
                hash_map_core(key, i);
                break;
            }
            key++;
            if (key >= DRV_MOUDLE_MAX)
                key = 0;
        } while (1);
        i++;

        if (i >= DRV_MOUDLE_MAX) {
            hm_panic("[error] hash map is full, please extend!\n");
            break;
        }
    }
}

static struct module_info *drv_find_module_by_name(const char *name)
{
    int32_t key;
    struct module_info *ptr = NULL;

    if (name == NULL) {
        hm_error("invalid name, please check\n");
        return NULL;
    }

    key = name[0] - 'a';
    if (key < 0)
        key += ('a' - 'A');

    do {
        ptr = (struct module_info *)g_hash_map[key];
        if (ptr == NULL || ptr->name == NULL)
            break;
        if (strncmp(name, ptr->name, strlen(name)) != 0) {
            key++;
            if (key < DRV_MOUDLE_MAX) {
                continue;
            } else {
                hm_error("can not find name\n");
                return NULL;
            }
        } else {
            return ptr;
        }
    } while (1);

    return NULL;
}

static struct module_info *find_module_by_id(int32_t id)
{
    uint32_t key = get_value_hash(id);

    for (uint32_t j = key; j < MAP_ID_MAX; j++) {
        if (g_hash_map_id[j].id == id)
            return drv_find_module_by_name(g_hash_map_id[j].name);
    }

    for (uint32_t k = 0; k < key; k++) {
        if (g_hash_map_id[k].id == id)
            return drv_find_module_by_name(g_hash_map_id[k].name);
    }

    return NULL;
}

tc_drv_syscall_t find_drv_syscall_by_id(int32_t id)
{
    struct module_info *module_info = find_module_by_id(id);
    if (module_info == NULL)
        return NULL;

    return (module_info->syscall);
}
