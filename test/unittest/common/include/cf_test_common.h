/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CF_TEST_COMMON_H
#define CF_TEST_COMMON_H

#include "cf_type.h"

namespace CertframeworkTest {
constexpr uint32_t PERFORMANCE_COUNT = 1000;

bool CompareBlob(const CfBlob *first, const CfBlob *second);

bool CompareOidArray(const CfBlobArray *firstArray, const CfBlobArray *secondArray);
}

#endif /* CF_TEST_COMMON_H */

