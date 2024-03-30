/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "utils.h"

#include <string.h>

#include "cf_log.h"
#include "cf_memory.h"

#define MIN_URL_LEN 5
#define HTTP_URL_LEN 7
#define HTTPS_URL_LEN 8

bool IsStrValid(const char *str, uint32_t maxLen)
{
    if (str == NULL) {
        LOGE("input string is NULL ptr");
        return false;
    }
    // One byte must be reserved for the terminator.
    if (strnlen(str, maxLen) >= maxLen) {
        LOGE("input string is beyond max length");
        return false;
    }
    return true;
}

bool IsBlobValid(const CfBlob *blob)
{
    return ((blob != NULL) && (blob->data != NULL) && (blob->size > 0));
}

bool IsClassMatch(const CfObjectBase *obj, const char *className)
{
    if ((obj == NULL) || (obj->getClass() == NULL) || (className == NULL)) {
        return false;
    }
    if (strcmp(obj->getClass(), className) == 0) {
        return true;
    } else {
        LOGE("class is not match. expect class: %s, input class: %s", className, obj->getClass());
        return false;
    }
}

bool IsPubKeyClassMatch(const HcfObjectBase *obj, const char *className)
{
    if ((obj == NULL) || (obj->getClass() == NULL) || (className == NULL)) {
        return false;
    }
    if (strcmp(obj->getClass(), className) == 0) {
        return true;
    } else {
        LOGE("class is not match. expect class: %s, input class: %s", className, obj->getClass());
        return false;
    }
}

bool IsUrlValid(const char *url)
{
    if (url == NULL) {
        return false;
    }
    if (strlen(url) < MIN_URL_LEN) {
        return false;
    }
    if (strncmp(url, "http://", HTTP_URL_LEN) != 0 && strncmp(url, "https://", HTTPS_URL_LEN) != 0) {
        return false;
    }

    int httpHeaderLen = (strncmp(url, "http://", HTTP_URL_LEN) == 0) ? HTTP_URL_LEN : HTTPS_URL_LEN;
    const char *startDomain = url + httpHeaderLen;
    const char *endDomain = startDomain;
    while (*endDomain != '\0' && *endDomain != '/') {
        endDomain++;
    }
    if (endDomain == startDomain) {
        return false;
    }

    if (*endDomain == '\0') {
        return true;
    } else {
        const char *startPath = endDomain;
        while (*startPath == '/') {
            startPath++;
        }
        if (*startPath == '\0') {
            return false;
        } else {
            return true;
        }
    }
    return false;
}

bool IsHttp(const char *url)
{
    if (url != NULL && strncmp(url, "http://", strlen("http://")) == 0) {
        return true;
    } else {
        return false;
    }
}