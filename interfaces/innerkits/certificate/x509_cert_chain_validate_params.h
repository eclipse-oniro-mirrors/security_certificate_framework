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

#ifndef X509_CERT_CHAIN_VALIDATE_PARAMETERS_H
#define X509_CERT_CHAIN_VALIDATE_PARAMETERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cert_crl_collection.h"
#include "cf_blob.h"
#include "x509_trust_anchor.h"

typedef struct HcfX509CertChainValidateParams HcfX509CertChainValidateParams;
struct HcfX509CertChainValidateParams {
    CfBlob *date;                                  // string
    HcfX509TrustAnchorArray *trustAnchors;         // Array<X509TrustAnchor>
    HcfCertCRLCollectionArray *certCRLCollections; // Array<CertCRLCollection>;
};

#endif // X509_CERT_CHAIN_VALIDATE_PARAMETERS_H
