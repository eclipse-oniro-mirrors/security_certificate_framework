/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef CF_X509_CERT_CHAIN_VALIDATOR_OPENSSL_PRIVATE_H
#define CF_X509_CERT_CHAIN_VALIDATOR_OPENSSL_PRIVATE_H

#include <stdint.h>
#include <string.h>
#include <time.h>
#include <securec.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bioerr.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>

#include "cf_blob.h"
#include "config.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "utils.h"
#include "cf_result.h"
#include "certificate_openssl_common.h"
#include "cert_chain_validator.h"
#include "x509_cert_chain_validator_openssl.h"
#include "revocation_cache_interface.h"
#include "x509_cert_chain_openssl.h"
#include "x509_cert_chain_openssl_ex.h"
#include "x509_crl_openssl.h"

#ifdef __cplusplus
extern "C" {
#endif

#define X509_CERT_CHAIN_VALIDATOR_OPENSSL_CLASS "X509CertChainValidatorOpensslClass"

#define MAX_TOTAL_DOWNLOAD_CERT_COUNT 5    // Max total download count
#define MAX_TOTAL_DOWNLOAD_COUNT 6    // Max total download count
#define MAX_INFO_ACCESS_TRAVERSE_COUNT 3  // Max traverse count for infoAccess
#define DOWNLOAD_TIMEOUT_SECONDS 3    // Download timeout in seconds
#define CRL_DOWNLOAD_TIMEOUT_SECONDS 3    // CRL download timeout in seconds
#define OCSP_REQUEST_TIMEOUT_SECONDS 4    // OCSP request timeout in seconds
#define MAX_WAIT_TIME_NANOSECONDS 1000000000 // Max wait time in nanoseconds
#define OCSP_RESPONSE_TIMEOUT_TIME 300
#define CRL_CACHE_FALLBACK_EXPIRE_SECONDS 86400    // CRL cache fallback expiry: 24 hours
#define OCSP_CACHE_FALLBACK_EXPIRE_SECONDS 14400   // OCSP cache fallback expiry: 4 hours
#define TM_YEAR_BASE 1900    // Year base for struct tm.tm_year

typedef struct CertsInfo {
    uint8_t *data;
    size_t len;
    X509 *x509;
} CertsInfo;

#define MAX_ERROR_MSG_BUF_LEN 512
#define MAX_SUBJECT_NAME_LEN 256

typedef struct CertVerifyResultInner {
    STACK_OF(X509) *certChain;
    char errorMsgBuf[MAX_ERROR_MSG_BUF_LEN];
    const char *errorMsg;
    int32_t errCode;
    X509 *lastCert;
    uint32_t usedMethod;
    int32_t revocationReason;
    char revocationTime[MAX_REVOCATION_TIME_LEN];
    X509 *revokedCert;
} CertVerifyResultInner;

typedef struct HcfX509CertValidatorOpenSSLParams {
    X509 *cert;
    X509 *issuer;
    X509_STORE *store;
    STACK_OF(X509) *untrustedCertStack;
    STACK_OF(X509) *certChain;
    time_t date;
    int ignoreErrs[MAX_IGNORE_ERR_COUNT + 1];
    bool ignoreOcspRespNotFound;
    bool ignoreNetworkTimeout;
    bool crlCheck;
    bool ocspCheck;
    bool preferOcsp;
    bool revocationCheckAll;
    bool certDup;
    bool cacheEnabled;
    X509_STORE *systemCaStore;
} HcfX509CertValidatorOpenSSLParams;

#define RETURN_VERIFY_ERROR(errorcode, errMsg, resultPtr) \
    do { \
        LOGE("%{public}d, %{public}s", (errorcode), (errMsg)); \
        (resultPtr)->errorMsg = (errMsg); \
        CfPrintOpensslError(); \
        return (errorcode); \
    } while (0)

/* OCSP response status time info */
typedef struct {
    ASN1_GENERALIZEDTIME *thisUpdate;
    ASN1_GENERALIZEDTIME *nextUpdate;
    ASN1_GENERALIZEDTIME *revocationTime;
    int reason;
} OcspTimeInfo;

/* OCSP connection info parsed from URL */
typedef struct {
    char *host;
    char *port;
    char *path;
    int useSsl;
    const char *url;
} OcspConnectInfo;

/* OCSP check context reused across URLs */
typedef struct {
    OCSP_REQUEST *req;
    OCSP_CERTID *certId;
    X509 *cert;
    int *remainingCount;
} OcspCheckContext;

/* KeyUsage type to OpenSSL KU_* bit mapping table */
extern const uint32_t KEYUSAGE_TO_OPENSSL_MAP[9];

extern const OpensslErrorToResult ERROR_TO_RESULT_MAP[8];

extern const OpensslErrorToResult ERROR_TO_RESULT_MAP_EX[11];

extern const OpensslErrorToResult X509_VERIFY_IGNORE_ERR_MAP[6];

CfResult CheckIpAddresses(X509 *x509, const HcfX509CertValidatorParams *params, CertVerifyResultInner *result);

CfResult CheckExtendedKeyUsage(X509 *x509, const HcfX509CertValidatorParams *params,
    CertVerifyResultInner *result);

void FormatRevocationTime(const ASN1_TIME *time, char *buf, size_t bufLen);

void FillCrlRevocationInfo(X509 *cert, const HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result);

uint64_t Asn1TimeToTimestamp(const ASN1_TIME *time);

uint64_t GetCrlExpirationTime(X509_CRL *crl);

void StoreOcspResponseToCache(X509 *cert, const HcfX509CertValidatorOpenSSLParams *opensslParams,
    OCSP_RESPONSE *resp, ASN1_GENERALIZEDTIME *nextUpdate);

bool IsTrustAnchorSystemCa(STACK_OF(X509) *certChain, X509_STORE *systemCaStore);

CfResult FillVerifyCertResult(STACK_OF(X509) *verifiedChain, HcfCertVerifyResult *result);

#define USER_DATA_INDEX 2
#ifdef __cplusplus
}
#endif

#endif // CF_X509_CERT_CHAIN_VALIDATOR_OPENSSL_PRIVATE_H