/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: register drv dyn policy
 * Create: 2021-07-22
 */

#include "drv_dyn_policy_mgr.h"
#include <tee_log.h>
#include <ac.h>
#include <ac_dynamic.h>
#include <ac_ex.h>
#include <cs.h>
#include <target_type.h>
#include "task_mgr.h"
#include "dyn_conf_dispatch_inf.h"

const char g_policy_drv_no_obj[] =
"op:1\n"
"get_uuid:1\n"
"AC_SID_ME:0\n"
;

static uint32_t get_policy_num(const struct drv_conf_t *drv_conf)
{
    uint32_t ret = 0;

    if (drv_conf == NULL)
        return 0;

    if (drv_conf->drv_basic_info.virt2phys)
        ret++;
    if (drv_conf->io_map_list_size > 0)
        ret++;
    if (drv_conf->irq_list_size > 0)
        ret++;
    if (drv_conf->map_secure_list_size > 0)
        ret++;
    if (drv_conf->map_nosecure_list_size > 0)
        ret++;

    return ret;
}

static void free_dynamic_policy(struct dynamic_policy *policy, uint32_t policy_num)
{
    uint32_t i;
    for (i = 0; i < policy_num; i++) {
        if (policy[i].objects != NULL) {
            free(policy[i].objects);
            policy[i].objects = NULL;
        }
    }
    free(policy);
}

static int32_t do_trans_dynamic_policy_iomap(uint32_t list_size, const void *list, struct dynamic_policy *policy)
{
    uint32_t i;
    const struct addr_region_t *io_map_list = (const struct addr_region_t *)list;
    for (i = 0; i < list_size; i++) {
        policy->objects[i].im_obj.paddr = io_map_list[i].start;
        if (io_map_list[i].end <= io_map_list[i].start) {
            tloge("io map invalid while trans dynamic policy iomap\n");
            return -1;
        }
        policy->objects[i].im_obj.size = io_map_list[i].end - io_map_list[i].start;
    }

    return 0;
}

static int32_t do_trans_dynamic_policy_irq(uint32_t list_size, const void *list, struct dynamic_policy *policy)
{
    uint32_t i;

    const uint64_t *irq_list = (const uint64_t *)list;
        for (i = 0; i < list_size; i++) {
            if (irq_list[i] < IRQ_MIN) {
                tloge("irq invalid while trans dynamic policy irq\n");
                return -1;
            }
            policy->objects[i].ia_obj.irq_no = irq_list[i];
        }

    return 0;
}

static int32_t do_trans_dynamic_policy_map_secure(uint32_t list_size, const void *list, struct dynamic_policy *policy)
{
    uint32_t i;
    const struct drv_map_secure_t *map_secure_list = (const struct drv_map_secure_t *)list;
    for (i = 0; i < list_size; i++) {
        if (memcpy_s(&policy->objects[i].ms_obj.uuid, sizeof(policy->objects[i].ms_obj.uuid),
                     &map_secure_list[i].uuid, sizeof(map_secure_list[i].uuid)) != 0) {
            tloge("memcpy for uuid failed\n");
            return -1;
        }
        policy->objects[i].ms_obj.paddr_start = map_secure_list[i].region.start;
        policy->objects[i].ms_obj.size = map_secure_list[i].region.end - map_secure_list[i].region.start;
    }

    return 0;
}

static int32_t do_trans_dynamic_policy_map_nosecure(uint32_t list_size, const void *list, struct dynamic_policy *policy)
{
    uint32_t i;
    const struct drv_map_nosecure_t *map_nosecure_list = (const struct drv_map_nosecure_t *)list;
    for (i = 0; i < list_size; i++) {
        if (memcpy_s(&policy->objects[i].mn_obj.uuid, sizeof(policy->objects[i].mn_obj.uuid),
                     &map_nosecure_list[i].uuid, sizeof(map_nosecure_list[i].uuid)) != 0) {
            tloge("memcpy for uuid failed\n");
            return -1;
        }
    }

    return 0;
}

static int32_t do_trans_drv_conf_to_dynamic_policy(struct tee_uuid subj_uuid, uint32_t type,
                                                   uint32_t list_size, const void *list,
                                                   struct dynamic_policy *policy)
{
    if (list == NULL) {
        tloge("invalid param in trans to dynamic policy\n");
        return -1;
    }

    if (memcpy_s(&policy->subj_uuid, sizeof(policy->subj_uuid), &subj_uuid, sizeof(subj_uuid)) != 0) {
        tloge("memcpy for uuid failed\n");
        return -1;
    }

    policy->type = type;
    policy->obj_cnt = list_size;

    if (list_size >= (MAX_IMAGE_LEN / sizeof(union obj_type))) {
        tloge("invalid list size\n");
        return -1;
    }

    policy->objects = malloc(list_size * sizeof(union obj_type));
    if (policy->objects == NULL) {
        tloge("malloc for uuid failed\n");
        return -1;
    }

    switch (type) {
    case IO_MAP_TYPE:
        if (do_trans_dynamic_policy_iomap(list_size, list, policy) != 0)
            goto err_out;
        break;
    case IRQ_ACQ_TYPE:
        if (do_trans_dynamic_policy_irq(list_size, list, policy) != 0)
            goto err_out;
        break;
    case MAP_SEC_TYPE:
        if (do_trans_dynamic_policy_map_secure(list_size, list, policy) != 0)
            goto err_out;
        break;
    case MAP_NONSEC_TYPE:
        if (do_trans_dynamic_policy_map_nosecure(list_size, list, policy) != 0)
            goto err_out;
        break;
    default:
        tloge("unknown type %u\n", type);
        goto err_out;
    }

    return 0;

err_out:
    free(policy->objects);
    policy->objects = NULL;
    return -1;
}

static int32_t do_add_virt2phys_dynamic_policy(struct tee_uuid subj_uuid, uint32_t type, struct dynamic_policy *policy)
{
    if (memcpy_s(&policy->subj_uuid, sizeof(policy->subj_uuid), &subj_uuid, sizeof(subj_uuid)) != 0) {
        tloge("memcpy for uuid failed\n");
        return -1;
    }

    policy->type = type;
    policy->obj_cnt = 0;
    policy->objects = NULL;

    return 0;
}

static int32_t trans_drv_conf_to_dynamic_policy_ex(struct tee_uuid uuid, const struct drv_conf_t *drv_conf,
                                                   struct dynamic_policy *policy, uint32_t policy_num)
{
    uint32_t idx = 0;
    if (drv_conf->drv_basic_info.virt2phys) {
        if (do_add_virt2phys_dynamic_policy(uuid, VIRT2PHY_TYPE, &policy[idx]) != 0)
            return -1;
        idx++;
    }

    if (drv_conf->io_map_list_size > 0 && idx < policy_num) {
        if (do_trans_drv_conf_to_dynamic_policy(uuid, IO_MAP_TYPE, drv_conf->io_map_list_size,
                                                drv_conf->io_map_list, &policy[idx]) != 0)
            return -1;
        idx++;
    }

    if (drv_conf->irq_list_size > 0 && idx < policy_num) {
        if (do_trans_drv_conf_to_dynamic_policy(uuid, IRQ_ACQ_TYPE, drv_conf->irq_list_size,
                                                drv_conf->irq_list, &policy[idx]) != 0)
            return -1;
        idx++;
    }

    if (drv_conf->map_secure_list_size > 0 && idx < policy_num) {
        if (do_trans_drv_conf_to_dynamic_policy(uuid, MAP_SEC_TYPE, drv_conf->map_secure_list_size,
                                                drv_conf->map_secure_list, &policy[idx]) != 0)
            return -1;
        idx++;
    }

    if (drv_conf->map_nosecure_list_size > 0 && idx < policy_num) {
        if (do_trans_drv_conf_to_dynamic_policy(uuid, MAP_NONSEC_TYPE, drv_conf->map_nosecure_list_size,
                                                drv_conf->map_nosecure_list, &policy[idx]) != 0)
            return -1;
    }

    return 0;
}

static struct dynamic_policy *trans_drv_conf_to_dynamic_policy(const struct task_tlv *tlv, uint32_t policy_num)
{
    uint32_t size = sizeof(struct dynamic_policy) * policy_num;

    if (size >= MAX_IMAGE_LEN) {
        tloge("invalid policy num %u\n", policy_num);
        return NULL;
    }

    struct dynamic_policy *policy = malloc(size);
    if (policy == NULL) {
        tloge("malloc for policy failed\n");
        return NULL;
    }

    if (memset_s(policy, size, 0, size) != 0) {
        tloge("memset for policy failed\n");
        free(policy);
        return NULL;
    }

    if (trans_drv_conf_to_dynamic_policy_ex(tlv->uuid, tlv->drv_conf, policy, policy_num) != 0) {
        tloge("trans for dyn policy failed\n");
        goto out;
    }

    return policy;

out:
    free_dynamic_policy(policy, policy_num);
    return NULL;
}

int32_t add_dynamic_policy_to_drv(const struct task_tlv *tlv)
{
    if (tlv == NULL) {
        tloge("invalid policy tlv param\n");
        return -1;
    }

    struct tee_uuid uuid = tlv->uuid;
    int32_t ret = ac_add_dynamic_policy(&uuid, g_policy_drv_no_obj, sizeof(g_policy_drv_no_obj) - 1, 0);
    if (ret != 0) {
        tloge("add policy:%s to drv:0x%x fail:0x%x\n", g_policy_drv_no_obj, uuid.timeLow, ret);
        return -1;
    }

    tlogd("add policy:%s to drv:0x%x succ\n", g_policy_drv_no_obj, uuid.timeLow);

    uint32_t policy_num = get_policy_num(tlv->drv_conf);
    if (policy_num > 0) {
        struct dynamic_policy *policy = trans_drv_conf_to_dynamic_policy(tlv, policy_num);
        if (policy == NULL) {
            tloge("trans drv conf to dynamic policy failed uuid:0x%x fail:0x%x\n", uuid.timeLow, ret);
            del_dynamic_policy_to_drv(&tlv->uuid);
            return -1;
        }

        ret = ac_add_dynamic_policy_ex(policy, policy_num);
        if (ret != 0) {
            tloge("add policy ex to drv:0x%x fail:0x%x\n", uuid.timeLow, ret);
            del_dynamic_policy_to_drv(&tlv->uuid);
        }
        free_dynamic_policy(policy, policy_num);
    }

    return ret;
}

void del_dynamic_policy_to_drv(const struct tee_uuid *uuid)
{
    if (uuid == NULL) {
        tloge("invalid uuid\n");
        return;
    }

    int32_t ret = ac_del_dynamic_policy(uuid);
    if (ret != 0)
        tloge("del drv:0x%x policy fail:0x%x\n", uuid->timeLow, ret);
    else
        tlogd("release drv:0x%x policy succ\n", uuid->timeLow);
}

int32_t register_drv_policy(struct task_node *node)
{
    if (node == NULL) {
        tloge("register invalid node\n");
        return -1;
    }

    if (node->target_type != DRV_TARGET_TYPE) {
        tloge("target_type: %d invalid\n", node->target_type);
        return -1;
    }

    int32_t ret = add_dynamic_policy_to_drv(&node->tlv);
    if (ret != 0)
        return -1;

    node->drv_task.register_policy = true;

    return 0;
}
