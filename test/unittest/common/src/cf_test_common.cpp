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

#include "cf_test_common.h"

#include <cstring>

bool CertframeworkTest::CompareBlob(const CfBlob *first, const CfBlob *second)
{
    if ((first == nullptr) || (second == nullptr) || (first->size != second->size)) {
        return false;
    }

    return (memcmp(first->data, second->data, first->size) == 0);
}

bool CertframeworkTest::CompareOidArray(const CfBlobArray *firstArray, const CfBlobArray *secondArray)
{
    if ((firstArray == nullptr) || (secondArray == nullptr) || (firstArray->count != secondArray->count)) {
        return false;
    }

    CfBlob *firstOids = firstArray->data;
    CfBlob *secondOids = secondArray->data;
    for (uint32_t i = 0; i < firstArray->count; i++) {
        if (CompareBlob(&firstOids[i], &secondOids[i]) != true) {
            return false;
        }
    }
    return true;
}
