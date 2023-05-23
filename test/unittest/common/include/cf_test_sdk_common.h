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

#ifndef CF_TEST_SDK_COMMON_H
#define CF_TEST_SDK_COMMON_H

#include "cf_type.h"

namespace CertframeworkSdkTest {
constexpr int32_t OP_TYPE_CHECK = 1;
constexpr int32_t OP_TYPE_GET = 2;

int32_t TestConstructParamSetIn(const CfParam *params, uint32_t cnt, CfParamSet **paramSet);

int32_t CommonTest(CfObjectType type, const CfEncodingBlob *inData,
    const CfParam *params, uint32_t cnt, CfParamSet **outParamSet);

int32_t AbnormalTest(CfObjectType objType, const CfEncodingBlob *in,
    const CfParam *params, uint32_t cnt, int32_t optype);

int32_t GetOutValue(const CfParamSet *resultParamSet);
}

#endif /* CF_TEST_SDK_COMMON_H */

