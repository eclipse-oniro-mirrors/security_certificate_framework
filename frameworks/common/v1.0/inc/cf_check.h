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

#ifndef CF_CHECK_H
#define CF_CHECK_H

#include <stdint.h>
#include "cf_blob.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CfCheckBlob(const CfBlob *blob, uint32_t maxLen);
int32_t CfCheckEncodingBlob(const CfEncodingBlob *blob, uint32_t maxLen);

#ifdef __cplusplus
}
#endif

#endif /* CF_CHECK_H */