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
#include "fwk_class.h"

#include <openssl/x509.h>

typedef struct {
    HcfX509CertChainSpi base;
    STACK_OF(X509) *x509CertChain;
    bool isOrder; // is an order chain
} HcfX509CertChainOpensslImpl;

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const EVP_MD *md;
    X509 *subjectCert;
    X509 *issuerCert;
} OcspCertIdInfo;

const char *GetX509CertChainClass(void);
CfResult CfToString(HcfX509CertChainSpi *self, CfBlob *out);
CfResult CfHashCode(HcfX509CertChainSpi *self, CfBlob *out);
X509 *GetX509FromHcfX509Certificate(const HcfCertificate *cert);
CfResult GetLeafCertsFromCertStack(
    const HcfX509CertChainBuildParameters *inParams, STACK_OF(X509) *allCerts, STACK_OF(X509) *leafCerts);
CfResult X509ToHcfX509Certificate(X509 *cert, HcfX509Certificate **returnObj);
void FreeResources(X509 *cert, EVP_PKEY *pkey, STACK_OF(X509) *caStack);
void FreeHcfX509P12Collection(HcfX509P12Collection *p12Collection);
CfResult AllocateAndConvertCert(X509 *cert, HcfX509P12Collection *collection, bool isGet);
CfResult AllocateAndConvertPkey(EVP_PKEY *pkey, HcfX509P12Collection *collection, bool isGet);
CfResult AllocateAndConvertCertStack(STACK_OF(X509) *ca, HcfX509P12Collection *collection, bool isGet);
void FreeCertificateArray(HcfX509CertificateArray *certs);
CfResult CfGetCertIdInfo(STACK_OF(X509) *x509CertChain, const CfBlob *ocspDigest, HcfX509TrustAnchor *trustAnchor,
    OcspCertIdInfo *certIdInfo, int index);
bool ContainsOption(HcfRevChkOpArray *options, HcfRevChkOption op);
CfResult IgnoreNetworkError(CfResult res, HcfRevChkOpArray *options);
CfResult SetVerifyParams(X509_STORE *store, X509 *mostTrustCert);
CfResult VerifyCertChain(X509 *mostTrustCert, STACK_OF(X509) *x509CertChain);
#ifdef __cplusplus
}
#endif

#endif // X509_CERT_CHAIN_OEPNSSL_EX_H
