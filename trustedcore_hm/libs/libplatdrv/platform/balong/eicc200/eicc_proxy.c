/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * foss@huawei.com
 *
 */

#include "eicc_platform.h"
#include "eicc_dts.h"
#include "eicc_proxy.h"
#include "eicc_device.h"
#include "eicc_driver.h"
#include "eicc_core.h"

static int eicc_proxy_shadow_ipipe_open(struct eicc_device *pdev, struct eicc_proxy_dts *pproxy_dts)
{
    struct eicc_device *p_relev_dev = NULL;
    struct ipipe_config ipipe_cfg;

    (void)memset_s(&ipipe_cfg, sizeof(struct ipipe_config), 0, sizeof(struct ipipe_config));

    ipipe_cfg.id = EICC_GET_PIPE_ID(pproxy_dts->ldrvchn_id);
    p_relev_dev = eicc_device_get_fast(EICC_GET_DEV_ID(pproxy_dts->rdrvchn_id));
    if (p_relev_dev == NULL) {
        eicc_print_error("eicc_device_get_fast relev device fail\n");
        return -1;
    }
    ipipe_cfg.relv_pipe_paddr = p_relev_dev->base_pa + EICC_IPIPE_BASE_ADDR_L(EICC_GET_PIPE_ID(pproxy_dts->rdrvchn_id));
    ipipe_cfg.ipipe_uctrl.union_stru.prior = 1;
    ipipe_cfg.ipipe_uctrl.union_stru.type = 0x2;
    ipipe_cfg.ipipe_uctrl.union_stru.arv_timeout = 1;

    eicc_shadow_ipipe_startup(pdev->base_va, &ipipe_cfg);

    eicc_ipipe_devint_en(pdev->base_va, EICC_GET_PIPE_ID(pproxy_dts->ldrvchn_id), EICC_INT_RD_PIPE_WAKEUP);
    eicc_ipipe_coreint_en(pdev->base_va, EICC_GET_PIPE_ID(pproxy_dts->ldrvchn_id),
                          EICC_GET_RCORE_ID(pproxy_dts->ldrvchn_id));

    eicc_ipipe_local_en(pdev->base_va, EICC_GET_PIPE_ID(pproxy_dts->ldrvchn_id));
    return 0;
}

int eicc_reset_proxy_shadow_ipipe_close(void)
{
    int ret;
    struct eicc_device *pdev = NULL;
    struct eicc_root_dts *parent_node = NULL;
    struct eicc_proxy_dts *pproxy_dts = NULL;

    parent_node = eicc_of_find_root_node();
    if (parent_node == NULL) {
        return 0;
    }
    for (pproxy_dts = eicc_of_get_first_proxynode(parent_node, NULL); pproxy_dts != NULL;
         pproxy_dts = eicc_of_get_next_proxynode(parent_node, pproxy_dts)) {
        pdev = eicc_device_get_fast(EICC_GET_DEV_ID(pproxy_dts->ldrvchn_id));
        if (pdev == NULL) {
            return -1;
        }

        if (pproxy_dts->const_flags & EICC_CHN_SF_MDMRST_CARE) {
            eicc_ipipe_local_dis(pdev->base_va, EICC_GET_PIPE_ID(pproxy_dts->ldrvchn_id));
            ret = ipipe_neg_check(pdev->base_va, EICC_GET_PIPE_ID(pproxy_dts->ldrvchn_id));
            if (ret == 0) {
                ret = ipipe_status_check(pdev->base_va, EICC_GET_PIPE_ID(pproxy_dts->ldrvchn_id));
            }
            if (ret) {
                eicc_print_error("eicc_reset_proxy_config_for_shadow_ipipe failed\n");
                return ret;
            }
        }
    }
    return 0;
}

int eicc_reset_proxy_shadow_ipipe_open(void)
{
    struct eicc_device *pdev = NULL;
    struct eicc_root_dts *parent_node = NULL;
    struct eicc_proxy_dts *pproxy_dts = NULL;

    parent_node = eicc_of_find_root_node();
    if (parent_node == NULL) {
        return 0;
    }
    for (pproxy_dts = eicc_of_get_first_proxynode(parent_node, NULL); pproxy_dts != NULL;
         pproxy_dts = eicc_of_get_next_proxynode(parent_node, pproxy_dts)) {
        pdev = eicc_device_get_fast(EICC_GET_DEV_ID(pproxy_dts->ldrvchn_id));
        if (pdev == NULL) {
            return -1;
        }
        if (pproxy_dts->const_flags & EICC_CHN_SF_MDMRST_CARE) {
            eicc_ipipe_local_en(pdev->base_va, EICC_GET_PIPE_ID(pproxy_dts->ldrvchn_id));
        }
    }
    return 0;
}

int eicc_proxy_init(void)
{
    int ret = 0;
    struct eicc_device *pdev = NULL;
    struct eicc_root_dts *parent_node = NULL;
    struct eicc_proxy_dts *pproxy_dts = NULL;

    parent_node = eicc_of_find_root_node();
    if (parent_node == NULL) {
        return 0;
    }
    for (pproxy_dts = eicc_of_get_first_proxynode(parent_node, NULL); pproxy_dts != NULL;
         pproxy_dts = eicc_of_get_next_proxynode(parent_node, pproxy_dts)) {
        pdev = eicc_device_get_fast(EICC_GET_DEV_ID(pproxy_dts->ldrvchn_id));
        if (pdev == NULL) {
            return -1;
        }
        eicc_core_unsec(pdev, EICC_GET_CORE_ID(pproxy_dts->ldrvchn_id));
        if (pproxy_dts->type == EICC_CHN_TYPE_MSG_INRRECV || pproxy_dts->type == EICC_CHN_TYPE_MSG_OUTRECV) {
            eicc_ipipe_unsec(pdev, EICC_GET_PIPE_ID(pproxy_dts->ldrvchn_id));
        } else {
            eicc_opipe_unsec(pdev, EICC_GET_PIPE_ID(pproxy_dts->ldrvchn_id));
        }
        if (pproxy_dts->type == EICC_CHN_TYPE_MSG_OUTSEND) {
            ret = eicc_proxy_shadow_ipipe_open(pdev, pproxy_dts);
            if (ret) {
                eicc_print_error("eicc_proxy_shadow_ipipe_open fail\n");
                return ret;
            }
        }
    }

    return ret;
}
