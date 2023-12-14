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

#include "cf_blob.h"

#include <securec.h>
#include "cf_memory.h"
#include "cf_log.h"
#include "cf_result.h"

void CfBlobFree(CfBlob **blob)
{
    if (blob == NULL) {
        return;
    }
    CfBlobDataFree(*blob);
    CfFree(*blob);
    *blob = NULL;
}

void CfBlobDataFree(CfBlob *blob)
{
    if ((blob == NULL) || (blob->data == NULL)) {
        return;
    }
    CfFree(blob->data);
    blob->data = NULL;
    blob->size = 0;
}

void CfBlobDataClearAndFree(CfBlob *blob)
{
    if ((blob == NULL) || (blob->data == NULL)) {
        LOGD("The input blob is null, no need to free.");
        return;
    }
    (void)memset_s(blob->data, blob->size, 0, blob->size);
    CfFree(blob->data);
    blob->data = NULL;
    blob->size = 0;
}

void CfEncodingBlobDataFree(CfEncodingBlob *encodingBlob)
{
    if ((encodingBlob == NULL) || (encodingBlob->data == NULL)) {
        LOGD("The input encodingBlob is null, no need to free.");
        return;
    }
    CfFree(encodingBlob->data);
    encodingBlob->data = NULL;
    encodingBlob->len = 0;
}

void CfArrayDataClearAndFree(CfArray *array)
{
    if (array == NULL) {
        LOGD("The input array is null, no need to free.");
        return;
    }
    for (uint32_t i = 0; i < array->count; ++i) {
        CfFree(array->data[i].data);
        array->data[i].data = NULL;
        array->data[i].size = 0;
    }
    array->count = 0;
    CfFree(array->data);
    array->data = NULL;
}

void FreeCfBlobArray(CfBlob *array, uint32_t arrayLen)
{
    if (array == NULL) {
        return;
    }

    for (uint32_t i = 0; i < arrayLen; ++i) {
        array[i].size = 0;
        CF_FREE_PTR(array[i].data);
    }

    CfFree(array);
}

bool CfBlobIsStr(const CfBlob *blob)
{
    if (blob == NULL || blob->data == NULL || blob->size == 0) {
        return false;
    }
    if (blob->data[blob->size - 1] == 0) {
        return true;
    }
    return false;
}
