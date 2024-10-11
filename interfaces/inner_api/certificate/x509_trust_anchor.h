/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef X509_TRUST_ANCHOR_H
#define X509_TRUST_ANCHOR_H

#include <stddef.h>
#include <stdint.h>

#include "cf_blob.h"
#include "x509_certificate.h"

typedef struct HcfX509TrustAnchor HcfX509TrustAnchor;
struct HcfX509TrustAnchor {
    CfBlob *CAPubKey;           // CAPubKey : Uint8Array DER format
    HcfX509Certificate *CACert; // CACert : X509Cert
    CfBlob *CASubject;          // CASubject : Uint8Array  DER format
    CfBlob *nameConstraints;
};

typedef struct {
    HcfX509TrustAnchor **data;
    uint32_t count;
} HcfX509TrustAnchorArray;

#endif // X509_TRUST_ANCHOR_H
