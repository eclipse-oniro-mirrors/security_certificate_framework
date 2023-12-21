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

#ifndef CF_CERTIFICATE_OPENSSL_COMMON_H
#define CF_CERTIFICATE_OPENSSL_COMMON_H

#include <stdint.h>

#include "cf_blob.h"
#include "cf_result.h"

#include <openssl/x509.h>

#define CF_OPENSSL_SUCCESS 1 /* openssl return 1: success */

#ifdef __cplusplus
extern "C" {
#endif

const char *GetAlgorithmName(const char *oid);
void CfPrintOpensslError(void);
CfResult DeepCopyDataToBlob(const unsigned char *data, uint32_t len, CfBlob *outBlob);
CfResult DeepCopyBlobToBlob(const CfBlob *inBlob, CfBlob **outBlob);
CfResult CopyExtensionsToBlob(const X509_EXTENSIONS *ext, CfBlob *outBlob);
CfResult ConvertNameDerDataToString(const unsigned char *data, uint32_t derLen, CfBlob *out);
CfResult CompareBigNum(const CfBlob *lhs, const CfBlob *rhs, int *out);
uint8_t *GetX509EncodedDataStream(const X509 *certificate, int *dataLength);
#ifdef __cplusplus
}
#endif

#endif
