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

#ifndef CF_CERT_ADAPTER_ABILITY_DEFINE_H
#define CF_CERT_ADAPTER_ABILITY_DEFINE_H

#include "cf_type.h"

typedef struct {
    CfBase base;
    int32_t (*adapterCreate)(const CfEncodingBlob *in, CfBase **object);
    void (*adapterDestory)(CfBase **object);
    int32_t (*adapterVerify)(const CfBase *certObj, const CfBlob *pubKey);
    int32_t (*adapterGetItem)(const CfBase *object, CfItemId id, CfBlob *outBlob);
} CfCertAdapterAbilityFunc;

#endif /* CF_CERT_ADAPTER_ABILITY_DEFINE_H */