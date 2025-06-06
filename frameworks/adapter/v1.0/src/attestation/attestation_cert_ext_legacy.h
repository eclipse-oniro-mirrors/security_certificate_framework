/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef ATTESTATION_CERT_EXT_LEGACY_H
#define ATTESTATION_CERT_EXT_LEGACY_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "cf_result.h"
#include "hm_attestation_cert_ext_type.h"

typedef struct LegacyKeyDescription LegacyKeyDescription;

#ifdef __cplusplus
extern "C" {
#endif

CfResult GetHmKeyDescription(const X509 *cert, LegacyKeyDescription **legacy);

void FreeHmKeyDescription(LegacyKeyDescription *legacy);

CfResult GetKeyDescriptionExt(LegacyKeyDescription *legacy, HmAttestationCertExtType type, HmAttestationCertExt *ext);

#ifdef __cplusplus
}
#endif

#endif // ATTESTATION_CERT_EXT_LEGACY_H
