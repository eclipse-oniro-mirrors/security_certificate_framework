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

#ifndef X509_CRL_ENTRY_OEPNSSL_H
#define X509_CRL_ENTRY_OEPNSSL_H

#include <openssl/x509.h>

#include "cf_blob.h"
#include "cf_result.h"
#include "x509_crl_entry.h"

#ifdef __cplusplus
extern "C" {
#endif

CfResult HcfCX509CRLEntryCreate(X509_REVOKED *rev, HcfX509CrlEntry **crlEntryOut, CfBlob *certIssuer);

#ifdef __cplusplus
}
#endif

#endif // X509_CRL_ENTRY_OEPNSSL_H
