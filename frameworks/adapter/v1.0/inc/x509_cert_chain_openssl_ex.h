/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef X509_CERT_CHAIN_OEPNSSL_EX_H
#define X509_CERT_CHAIN_OEPNSSL_EX_H

#include "cf_result.h"
#include "x509_cert_chain.h"
#include "x509_cert_chain_spi.h"
#include "x509_certificate.h"

#include <openssl/x509.h>

typedef struct {
    HcfX509CertChainSpi base;
    STACK_OF(X509) * x509CertChain;
    bool isOrder; // is an order chain
} HcfX509CertChainOpensslImpl;

#ifdef __cplusplus
extern "C" {
#endif

const char *GetX509CertChainClass(void);
CfResult ToString(HcfX509CertChainSpi *self, CfBlob *out);
CfResult HashCode(HcfX509CertChainSpi *self, CfBlob *out);

#ifdef __cplusplus
}
#endif

#endif // X509_CERT_CHAIN_OEPNSSL_EX_H
