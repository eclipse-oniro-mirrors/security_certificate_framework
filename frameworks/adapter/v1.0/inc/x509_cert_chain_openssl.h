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

#ifndef X509_CERT_CHAIN_OEPNSSL_H
#define X509_CERT_CHAIN_OEPNSSL_H

#include "cf_result.h"
#include "x509_cert_chain.h"
#include "x509_cert_chain_spi.h"
#include "x509_certificate.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_CERT_NUM 256 /* max certs number of a certchain */
#define TIMET_NUM 6
#define TIMET_YEAR_START 1900
#define TIMET_YEAR_OFFSET 100 // start time year from 1900 + 100
#define TRY_CONNECT_TIMES 3
#define OCSP_CONN_MILLISECOND 5000 // millisecond
#define OCSP_CONN_TIMEOUT (-1)     // timeout == 0 means no timeout, < 0 means exactly one try.
#define LOAD_OCSP_CONN_TIMEOUT 5     // 5 second timeout.
#define HTTP_PORT "80"
#define HTTPS_PORT "443"
#define CERT_VERIFY_DIR "/etc/security/certificates"

// helper functions
typedef struct {
    int32_t errCode;
    CfResult result;
} OpensslErrorToResult;

typedef enum {
    CF_DOWNLOAD_MISSING_INTERMEDIATE_CERT = 1,
} CfScenarioType;

typedef struct {
    CfResult errCode;
    CfScenarioType scenario;
} ErrorCodeConvertInfo;

CfResult HcfX509CertChainByEncSpiCreate(const CfEncodingBlob *inStream, HcfX509CertChainSpi **spi);
CfResult HcfX509CertChainByArrSpiCreate(const HcfX509CertificateArray *inCerts, HcfX509CertChainSpi **spi);
CfResult HcfX509CertChainByParamsSpiCreate(const HcfX509CertChainBuildParameters *inParams, HcfX509CertChainSpi **spi);
CfResult HcfX509CreateTrustAnchorWithKeyStoreFunc(
    const CfBlob *keyStore, const CfBlob *pwd, HcfX509TrustAnchorArray **trustAnchorArray);
CfResult HcfX509ParsePKCS12Func(
    const CfBlob *keyStore, const HcfParsePKCS12Conf *conf, HcfX509P12Collection **p12Collection);
CfResult HcfCreatePkcs12Func(HcfX509P12Collection *p12Collection, HcfPkcs12CreatingConfig *conf, CfBlob *blob);
#ifdef __cplusplus
}
#endif

#endif // X509_CERT_CHAIN_OEPNSSL_H
