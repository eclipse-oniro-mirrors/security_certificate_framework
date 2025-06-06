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

#ifndef HM_ATTESSTATION_COMMON_H
#define HM_ATTESSTATION_COMMON_H

#include <stdbool.h>
#include "openssl/x509.h"
#include "openssl/asn1t.h"
#include "cf_result.h"
#include "cf_blob.h"

#ifdef __cplusplus
extern "C" {
#endif

bool CmpObjOid(ASN1_OBJECT *obj, const uint8_t *oid, uint32_t oidLen);
CfResult FindCertExt(const X509 *cert, const uint8_t *oid, uint32_t oidLen, X509_EXTENSION **extension);
CfResult GetOctectOrUtf8Data(ASN1_TYPE *v, CfBlob *out);

#ifdef __cplusplus
}
#endif

#endif // HM_ATTESSTATION_COMMON_H
