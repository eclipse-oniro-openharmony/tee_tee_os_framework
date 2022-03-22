/*
* Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
* Description: common interface file
* Author: l00492120 & c00414356
* Create: 2017-01-20
* Notes: this file's api is for all TP modules wrapper interface
*/
#include "thp_afe.h"
#include "thp_afe_debug.h"
#include "tee_log.h"
#include "thp_afe_wrapper.h"
#include <string.h>

thp_afe_api* g_afe_api_wrapper = NULL;
char*  g_tsa_projectid = NULL;

const int MAX_PROJECT_ID_NUM = 10;
int thp_afe_wrapper_init(const char* projectId)
{
    bool match = false;
    unsigned char counter = 0;

    if (projectId == NULL) {
        tloge("projectId is null");
        return TRADITION;
    }

    while (!match && g_afe_api_type[counter] != NULL) {
        if (!strncmp(projectId, g_projectid_text[counter], MAX_PROJECT_ID_NUM))
            match = true;
        else
            counter++;
    }

    if (match) {
        g_afe_api_wrapper = g_afe_api_type[counter];
        g_tsa_projectid = g_projectid_text[counter];
        tloge("projectid[%d] = %s !! \n", counter, g_tsa_projectid);
    } else {
        g_afe_api_wrapper = NULL;
        tloge("can't find the thp projectid, maybe it's tradition Solution !! \n");
        return TRADITION;
    }

    return 0;
}

#ifdef __cplusplus
}
#endif

