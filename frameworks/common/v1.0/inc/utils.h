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

#ifndef CF_UTILS_H
#define CF_UTILS_H

#include <stdbool.h>
#include <stdint.h>

#include "cf_blob.h"
#include "cf_object_base.h"
#include "object_base.h"

#ifdef __cplusplus
extern "C" {
#endif

bool IsStrValid(const char *str, uint32_t maxLen);
bool IsBlobValid(const CfBlob *blob);
bool IsClassMatch(const CfObjectBase *obj, const char *className);
bool IsPubKeyClassMatch(const HcfObjectBase *obj, const char *className);
bool IsUrlValid(const char *url);
bool IsHttp(const char *url);

#ifdef __cplusplus
}
#endif

#endif
