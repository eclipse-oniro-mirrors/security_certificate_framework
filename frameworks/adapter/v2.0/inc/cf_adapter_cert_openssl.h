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

#ifndef CF_ADAPTER_CERT_H
#define CF_ADAPTER_CERT_H

#include <openssl/x509.h>

#include "cf_type.h"

#define ASN1_TAG_TYPE_SEQ 0x30

typedef struct {
    CfBase base; /* type verify for cert object */
    X509 *x509Cert;
} CfOpensslCertObj;

#ifdef __cplusplus
extern "C" {
#endif

int32_t CfOpensslCreateCert(const CfEncodingBlob *inData, CfBase **object);

void CfOpensslDestoryCert(CfBase **object);

int32_t CfOpensslVerifyCert(const CfBase *certObj, const CfBlob *pubKey);

int32_t CfOpensslGetCertItem(const CfBase *object, CfItemId id, CfBlob *outBlob);

#ifdef __cplusplus
}
#endif

#endif /* CF_ADAPTER_CERT_H */