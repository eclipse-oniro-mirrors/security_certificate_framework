/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef CF_LOG_H
#define CF_LOG_H

#include <stdint.h>
#include <stdlib.h>

#ifdef HILOG_ENABLE

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#include "hilog/log.h"

#undef LOG_TAG
#define LOG_TAG "CertFramework"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002F17 /* CertFramework's domain id */

#define CF_LOG_D(fmt, ...) \
HILOG_DEBUG(LOG_CORE, "%{public}s[%{public}u]: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define CF_LOG_I(fmt, ...) \
HILOG_INFO(LOG_CORE, "%{public}s[%{public}u]: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define CF_LOG_W(fmt, ...) \
HILOG_WARN(LOG_CORE, "%{public}s[%{public}u]: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define CF_LOG_E(fmt, ...) \
HILOG_ERROR(LOG_CORE, "%{public}s[%{public}u]: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

#else

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#define CF_LOG_FILE "certificate_framework.log"
#define CF_LOG_BUF_SIZE 512
#define CF_PUBLIC_TAG "{public}"

static void CfPrintLog(const char *level, const char *file, int line, const char *func, const char *fmt, ...)
{
    const char *slash = strrchr(file, '/');
    const char *filename = (slash != NULL) ? slash + 1 : file;
    size_t publicTagLen = sizeof(CF_PUBLIC_TAG) - 1;

    char buf[CF_LOG_BUF_SIZE + 1] = {};
    char *dst = buf;
    const char *src = fmt;
    while (*src && (size_t)(dst - buf) < sizeof(buf)) {
        if (strncmp(src, CF_PUBLIC_TAG, publicTagLen) == 0) {
            src += publicTagLen;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';

    FILE *fp = fopen(CF_LOG_FILE, "a");
    if (fp == NULL) {
        fp = stderr;
    }

    time_t now = time(NULL);
    struct tm t = {};
    char ts[] = "0000-00-00 00:00:00";
    (void)localtime_r(&now, &t);
    (void)strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &t);

    (void)fprintf(fp, "[%s] [%s] [%s:%d] [%s] ", ts, level, filename, line, func);

    va_list args;
    va_start(args, fmt);
    (void)vfprintf(fp, buf, args);
    va_end(args);
    (void)fprintf(fp, "\n");

    if (fp != stderr) {
        fclose(fp);
    }
}

#define CF_LOG_D(fmt, ...) CfPrintLog("DEBUG", __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define CF_LOG_I(fmt, ...) CfPrintLog("INFO",  __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define CF_LOG_W(fmt, ...) CfPrintLog("WARN",  __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#define CF_LOG_E(fmt, ...) CfPrintLog("ERROR", __FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)

#endif

#define LOGD CF_LOG_D
#define LOGI CF_LOG_I
#define LOGW CF_LOG_W
#define LOGE CF_LOG_E

#endif
