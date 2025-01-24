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

#ifndef X509_CERTIFICATE_CREATE_H
#define X509_CERTIFICATE_CREATE_H

#include "cf_blob.h"
#include "x509_certificate.h"

typedef CfResult (*HcfX509CertCreateFunc)(const CfEncodingBlob *, HcfX509Certificate **);

#ifdef __cplusplus
extern "C" {
#endif

void SetHcfX509CertCreateFunc(HcfX509CertCreateFunc func);
HcfX509CertCreateFunc GetHcfX509CertCreateFunc(void);

#ifdef __cplusplus
}
#endif

#endif // X509_CERTIFICATE_CREATE_H
