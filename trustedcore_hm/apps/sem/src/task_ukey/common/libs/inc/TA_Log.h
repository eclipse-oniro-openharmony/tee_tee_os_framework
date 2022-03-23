#ifndef TA_LOG_H
#define TA_LOG_H
#include <tee_log.h>

#define LOGD(fmt, args...) SLog("%d: " fmt "\n",  __LINE__, ## args)
#define LOGE(fmt, args...) SLog("%d: " fmt "\n",  __LINE__, ## args)
#define LOGI(fmt, args...) SLog("%d: " fmt "\n",  __LINE__, ## args)
#define LOGS(fmt, args...) SLog("%d: " fmt "\n",  __LINE__, ## args)

#endif
