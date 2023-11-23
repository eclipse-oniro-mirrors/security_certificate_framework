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

#ifndef CF_ADAPTER_EXTENSION_H
#define CF_ADAPTER_EXTENSION_H

#include <openssl/x509.h>

#include "cf_type.h"

typedef struct {
    CfBase base;
    X509_EXTENSIONS *exts;
} CfOpensslExtensionObj;

#ifdef __cplusplus
extern "C" {
#endif

int32_t CfOpensslCreateExtension(const CfEncodingBlob *inData, CfBase **object);

void CfOpensslDestoryExtension(CfBase **object);

int32_t CfOpensslGetOids(const CfBase *object, CfExtensionOidType type, CfBlobArray *out);

int32_t CfOpensslGetEntry(const CfBase *object, CfExtensionEntryType type, const CfBlob *oid, CfBlob *out);

int32_t CfOpensslCheckCA(const CfBase *object, int32_t *pathLen);

int32_t CfOpensslGetExtensionItem(const CfBase *object, CfItemId id, CfBlob *out);

int32_t CfOpensslHasUnsupportedCriticalExtension(const CfBase *object, bool *out);

#ifdef __cplusplus
}
#endif

#endif /* CF_ADAPTER_EXTENSION_H */