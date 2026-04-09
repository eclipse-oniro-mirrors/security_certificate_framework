/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cf_err_msg.h"

#include <stdarg.h>
#include <securec.h>

#include "cf_log.h"
#include "cf_memory.h"

void CfBuildErrorMsg(char **errMsg, const char *format, ...)
{
    if (errMsg == NULL) {
        return;
    }
    CF_FREE_PTR(*errMsg);
    char *buf = (char *)CfMallocEx(CF_MAX_PARAM_ERR_MSG_LEN);
    if (buf == NULL) {
        return;
    }
    va_list args;
    va_start(args, format);
    if (vsnprintf_s(buf, CF_MAX_PARAM_ERR_MSG_LEN, CF_MAX_PARAM_ERR_MSG_LEN - 1, format, args) <= 0) {
        LOGE("CfBuildErrorMsg vsnprintf_s failed");
        CF_FREE_PTR(buf);
        return;
    }
    va_end(args);
    *errMsg = buf;
    LOGE("%{public}s", buf);
}