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

#include "cf_param_parse.h"

#include "securec.h"

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_param.h"
#include "cf_result.h"

int32_t CfConstructParamSetOut(const CfParam *params, uint32_t cnt, CfParamSet **out)
{
    CfParamSet *tmp = NULL;
    int32_t ret = CfInitParamSet(&tmp);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("init out paramset failed");
        return ret;
    }

    ret = CfAddParams(tmp, params, cnt);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("add out param failed");
        CfFreeParamSet(&tmp);
        return ret;
    }

    ret = CfBuildParamSet(&tmp);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("build out paramSet failed");
        CfFreeParamSet(&tmp);
        return ret;
    }

    *out = tmp;
    return CF_SUCCESS;
}

int32_t CfConstructArrayParamSetOut(const CfBlobArray *array, CfParamSet **out)
{
    CfParamSet *tmp = NULL;
    int32_t ret;
    do {
        ret = CfInitParamSet(&tmp);
        if (ret != CF_SUCCESS) {
            CF_LOG_E("init out paramset failed");
            break;
        }

        CfParam typeParam = { .tag = CF_TAG_RESULT_TYPE, .int32Param = CF_TAG_TYPE_BYTES };
        ret = CfAddParams(tmp, &typeParam, 1);
        if (ret != CF_SUCCESS) {
            CF_LOG_E("add out param type failed");
            break;
        }

        for (uint32_t i = 0; i < array->count; ++i) {
            CfParam param = { .tag = CF_TAG_RESULT_BYTES, .blob = array->data[i] };
            ret = CfAddParams(tmp, &param, 1);
            if (ret != CF_SUCCESS) {
                CF_LOG_E("add out param data failed");
                break;
            }
        }

        ret = CfBuildParamSet(&tmp);
        if (ret != CF_SUCCESS) {
            CF_LOG_E("build out paramSet failed");
            break;
        }

        *out = tmp;
        return CF_SUCCESS;
    } while (0);

    CfFreeParamSet(&tmp);
    return ret;
}