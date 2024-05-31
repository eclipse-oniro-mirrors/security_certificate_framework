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

#include "cf_param.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "securec.h"

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"

CfTagType CfGetTagType(CfTag tag)
{
    return (CfTagType)((uint32_t)tag & CF_TAG_TYPE_MASK);
}

int32_t CfInitParamSet(CfParamSet **paramSet)
{
    if (paramSet == NULL) {
        CF_LOG_E("invalid init params!");
        return CF_NULL_POINTER;
    }

    *paramSet = (CfParamSet *)CfMalloc(CF_DEFAULT_PARAM_SET_SIZE, 0);
    if (*paramSet == NULL) {
        CF_LOG_E("malloc init param set failed!");
        return CF_ERR_MALLOC;
    }
    (*paramSet)->paramsCnt = 0;
    (*paramSet)->paramSetSize = sizeof(CfParamSet);
    return CF_SUCCESS;
}

static int32_t CfCheckParamSet(const CfParamSet *paramSet, uint32_t size)
{
    if ((size < sizeof(CfParamSet)) || (size > CF_PARAM_SET_MAX_SIZE) ||
        (paramSet->paramSetSize != size) ||
        (paramSet->paramsCnt > ((size - sizeof(CfParamSet)) / sizeof(CfParam)))) {
        CF_LOG_E("invalid param set!");
        return CF_INVALID_PARAMS;
    }
    return CF_SUCCESS;
}

static int32_t CfFreshParamSet(CfParamSet *paramSet, bool isCopy)
{
    int32_t ret = CfCheckParamSet(paramSet, paramSet->paramSetSize);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("invalid fresh paramSet");
        return ret;
    }

    uint32_t size = paramSet->paramSetSize;
    uint32_t offset = sizeof(CfParamSet) + sizeof(CfParam) * paramSet->paramsCnt;

    for (uint32_t i = 0; i < paramSet->paramsCnt; i++) {
        if (offset > size) {
            CF_LOG_E("invalid param set offset!");
            return CF_INVALID_PARAMS;
        }
        if (CfGetTagType(paramSet->params[i].tag) == CF_TAG_TYPE_BYTES) {
            if (CfIsAdditionOverflow(offset, paramSet->params[i].blob.size)) {
                CF_LOG_E("blob size overflow!");
                return CF_INVALID_PARAMS;
            }

            if (isCopy && (memcpy_s((uint8_t *)paramSet + offset, size - offset,
                paramSet->params[i].blob.data, paramSet->params[i].blob.size) != EOK)) {
                CF_LOG_E("copy param blob failed!");
                return CF_ERR_COPY;
            }
            paramSet->params[i].blob.data = (uint8_t *)paramSet + offset;
            offset += paramSet->params[i].blob.size;
        }
    }

    if (paramSet->paramSetSize != offset) {
        CF_LOG_E("invalid param set size!");
        return CF_INVALID_PARAMS;
    }
    return CF_SUCCESS;
}

static int32_t BuildParamSet(CfParamSet **paramSet)
{
    CfParamSet *freshParamSet = *paramSet;
    uint32_t size = freshParamSet->paramSetSize;
    uint32_t offset = sizeof(CfParamSet) + sizeof(CfParam) * freshParamSet->paramsCnt;

    if (size > CF_DEFAULT_PARAM_SET_SIZE) {
        freshParamSet = (CfParamSet *)CfMalloc(size, 0);
        if (freshParamSet == NULL) {
            CF_LOG_E("malloc params failed!");
            return CF_ERR_MALLOC;
        }
        if (memcpy_s(freshParamSet, size, *paramSet, offset) != EOK) {
            CF_FREE_PTR(freshParamSet);
            CF_LOG_E("copy params failed!");
            return CF_ERR_COPY;
        }
        CF_FREE_PTR(*paramSet);
        *paramSet = freshParamSet;
    }

    return CfFreshParamSet(freshParamSet, true);
}

int32_t CfBuildParamSet(CfParamSet **paramSet)
{
    if ((paramSet == NULL) || (*paramSet == NULL)) {
        return CF_NULL_POINTER;
    }

    int ret = CfCheckParamSet(*paramSet, (*paramSet)->paramSetSize);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("invalid build params!");
        return ret;
    }

    return BuildParamSet(paramSet);
}

void CfFreeParamSet(CfParamSet **paramSet)
{
    if (paramSet == NULL) {
        CF_LOG_E("invalid free paramset!");
        return;
    }
    CF_FREE_PTR(*paramSet);
}

int32_t CfGetParam(const CfParamSet *paramSet, uint32_t tag, CfParam **param)
{
    if ((paramSet == NULL) || (param == NULL)) {
        CF_LOG_E("invalid params!");
        return CF_NULL_POINTER;
    }

    if (CfCheckParamSet(paramSet, paramSet->paramSetSize) != CF_SUCCESS) {
        CF_LOG_E("invalid paramSet!");
        return CF_INVALID_PARAMS;
    }

    for (uint32_t i = 0; i < paramSet->paramsCnt; i++) {
        if (tag == paramSet->params[i].tag) {
            *param = (CfParam *)&paramSet->params[i];
            return CF_SUCCESS;
        }
    }

    return CF_NOT_EXIST;
}

static int32_t CheckBeforeAddParams(const CfParamSet *paramSet, const CfParam *params,
    uint32_t paramCnt)
{
    if ((params == NULL) || (paramSet == NULL) || (paramSet->paramSetSize > CF_PARAM_SET_MAX_SIZE) ||
        (paramCnt > CF_DEFAULT_PARAM_CNT) || ((paramSet->paramsCnt + paramCnt) > CF_DEFAULT_PARAM_CNT)) {
        CF_LOG_E("invalid params or paramset!");
        return CF_INVALID_PARAMS;
    }

    for (uint32_t i = 0; i < paramCnt; i++) {
        if ((CfGetTagType(params[i].tag) == CF_TAG_TYPE_BYTES) &&
            ((params[i].blob.data == NULL) || (params[i].blob.size == 0))) {
            CF_LOG_E("invalid blob param!");
            return CF_INVALID_PARAMS;
        }
    }
    return CF_SUCCESS;
}

int32_t CfAddParams(CfParamSet *paramSet, const CfParam *params, uint32_t paramCnt)
{
    int32_t ret = CheckBeforeAddParams(paramSet, params, paramCnt);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    for (uint32_t i = 0; i < paramCnt; i++) {
        if (paramSet->paramSetSize > CF_PARAM_SET_MAX_SIZE) {
            CF_LOG_E("params size[%u] too large!", paramSet->paramSetSize);
            return CF_INVALID_PARAMS;
        }
        paramSet->paramSetSize += sizeof(CfParam);
        if (CfGetTagType(params[i].tag) == CF_TAG_TYPE_BYTES) {
            if (CfIsAdditionOverflow(paramSet->paramSetSize, params[i].blob.size)) {
                CF_LOG_E("params size overflow!");
                paramSet->paramSetSize -= sizeof(CfParam);
                return CF_INVALID_PARAMS;
            }
            paramSet->paramSetSize += params[i].blob.size;
        }
        (void)memcpy_s(&paramSet->params[paramSet->paramsCnt++], sizeof(CfParam), &params[i], sizeof(CfParam));
    }
    return CF_SUCCESS;
}
