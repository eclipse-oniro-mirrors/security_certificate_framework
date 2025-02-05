/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "x509_certificate_create.h"

static HcfX509CertCreateFunc g_hcfX509CertCreateFunc = NULL;

void SetHcfX509CertCreateFunc(HcfX509CertCreateFunc func)
{
    g_hcfX509CertCreateFunc = func;
}

HcfX509CertCreateFunc GetHcfX509CertCreateFunc(void)
{
    return g_hcfX509CertCreateFunc;
}
