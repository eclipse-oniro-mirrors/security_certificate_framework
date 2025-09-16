/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "ani_object.h"

namespace ANI::CertFramework {
CfResult DoCommonOperation(const CfObject *object, const std::vector<CfParam> &param,
    CfParamSet **outParamSet, std::string &errMsg)
{
    if (object == nullptr) {
        errMsg = "object is nullptr!";
        return CF_INVALID_PARAMS;
    }
    CfParamSet *inParamSet = nullptr;
    CfResult res = static_cast<CfResult>(CfInitParamSet(&inParamSet));
    if (res != CF_SUCCESS) {
        errMsg = "init param set failed!";
        return res;
    }
    res = static_cast<CfResult>(CfAddParams(inParamSet, param.data(), param.size()));
    if (res != CF_SUCCESS) {
        CfFreeParamSet(&inParamSet);
        errMsg = "add params failed!";
        return res;
    }
    if (param.front().tag == CF_TAG_GET_TYPE) {
        res = static_cast<CfResult>(object->get(object, inParamSet, outParamSet));
    } else { // CF_TAG_CHECK_TYPE
        res = static_cast<CfResult>(object->check(object, inParamSet, outParamSet));
    }
    CfFreeParamSet(&inParamSet);
    if (res != CF_SUCCESS) {
        errMsg = (param[0].tag == CF_TAG_GET_TYPE ? "get failed!" : "check failed!");
        return res;
    }
    return CF_SUCCESS;
}
} // namespace ANI::CertFramework
