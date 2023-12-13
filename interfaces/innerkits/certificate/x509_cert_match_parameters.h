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

#ifndef X509_CERT_MATCH_PARAMETERS_H
#define X509_CERT_MATCH_PARAMETERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cf_blob.h"
#include "certificate.h"

typedef struct HcfX509CertMatchParams HcfX509CertMatchParams;
struct HcfX509CertMatchParams {
    HcfCertificate *x509Cert;
    CfBlob *validDate;
    CfBlob *issuer;
    CfBlob *keyUsage;
    CfBlob *serialNumber;
    CfBlob *subject;
    CfBlob *publicKey;
    CfBlob *publicKeyAlgID;
};

#endif // X509_CERT_MATCH_PARAMETERS_H
