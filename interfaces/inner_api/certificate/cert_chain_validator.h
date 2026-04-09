/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#ifndef CF_CERT_CHAIN_VALIDATOR_H
#define CF_CERT_CHAIN_VALIDATOR_H

#include <stddef.h>
#include <stdint.h>
#include "cf_blob.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "x509_cert_chain_validate_params.h"
#include "x509_cert_chain_validate_result.h"

typedef struct HcfCertChainValidator HcfCertChainValidator;

typedef struct HcfCertChainData {
    uint8_t *data;
    uint32_t dataLen;
    uint8_t count;
    enum CfEncodingFormat format;
} HcfCertChainData;

typedef enum {
    OCSP_DIGEST_SHA1   = 0,
    OCSP_DIGEST_SHA224 = 1,
    OCSP_DIGEST_SHA256 = 2,
    OCSP_DIGEST_SHA384 = 3,
    OCSP_DIGEST_SHA512 = 4
} HcfOcspDigest;

typedef enum {
    CERT_REVOCATION_PREFER_OCSP     = 0,
    CERT_REVOCATION_CRL_CHECK       = 1,
    CERT_REVOCATION_OCSP_CHECK      = 2,
    CERT_REVOCATION_CHECK_ALL_CERT  = 3,
} HcfCertRevocationFlag;

typedef struct HcfResultArray {
    CfResult *data;
    uint32_t count;
} HcfResultArray;

typedef struct HcfInt32Array {
    int32_t *data;
    uint32_t count;
} HcfInt32Array;

typedef struct HcfX509CertRevokedParams {
    HcfInt32Array revocationFlags;
    HcfX509CrlArray crls;
    bool allowDownloadCrl;
    bool allowOcspCheckOnline;
    CfBlobArray ocspResponses;
    int32_t ocspDigest;
} HcfX509CertRevokedParams;


#define MAX_REVOCATION_FLAG_COUNT 4
#define MAX_CRL_COUNT 100
#define MAX_OCSP_RESPONSE_COUNT 100
#define MAX_UNTRUSTED_CERT_COUNT 100
#define MAX_TRUSTED_CERT_COUNT 100
#define MAX_IGNORE_ERR_COUNT 8
#define MAX_HOSTNAMES_COUNT 100
#define MAX_KEYUSAGE_COUNT 9
#define MAX_EMAIL_ADDRESS_COUNT 1
#define MAX_HOSTNAME_LENGTH 128
#define MAX_EMAIL_ADDRESS_LENGTH 128
#define MAX_USER_ID_LEN 128

#define MIN_DATE_LEN 13
#define MAX_DATE_LEN 15

// for ignoreErrs
#define CERT_NOT_YET_VALID 19030003
#define CERT_HAS_EXPIRED 19030004
#define CERT_UNKNOWN_CRITICAL_EXTENSION 19030011
#define CRL_NOT_FOUND 19030015
#define CRL_NOT_YET_VALID 19030016
#define CRL_HAS_EXPIRED 19030017
#define OCSP_RESPONSE_NOT_FOUND 19030020
#define NETWORK_TIMEOUT 19030024

typedef struct HcfX509CertValidatorParams {
    HcfX509CertificateArray untrustedCerts;
    HcfX509CertificateArray trustedCerts;
    bool trustSystemCa;
    bool partialChain;
    bool allowDownloadIntermediateCa;
    bool validateDate;
    char *date;
    HcfInt32Array ignoreErrs;
    HcfStringArray hostnames;
    HcfStringArray emailAddresses;
    HcfInt32Array keyUsage;
    CfBlob userId;
    HcfX509CertRevokedParams *revokedParams;
} HcfX509CertValidatorParams;

#define MAX_VERIFY_ERROR_MSG_LEN 512

typedef struct {
    HcfX509CertificateArray certs;
    char errorMsgBuf[MAX_VERIFY_ERROR_MSG_LEN];
    const char *errorMsg;
} HcfVerifyCertResult;


struct HcfCertChainValidator {
    struct CfObjectBase base;

    /** verify the cert chain. */
    CfResult (*validate)(HcfCertChainValidator *self, const HcfCertChainData *certChainData);

    /** Get algorithm name. */
    const char *(*getAlgorithm)(HcfCertChainValidator *self);

    /** validate a single X509 certificate with parameters. */
    CfResult (*validateX509Cert)(HcfCertChainValidator *self, HcfX509Certificate *cert,
        const HcfX509CertValidatorParams *params, HcfVerifyCertResult *result);
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate cert chain validator instance.
 */
CfResult HcfCertChainValidatorCreate(const char *algorithm, HcfCertChainValidator **pathValidator);

#ifdef __cplusplus
}
#endif

#endif // CF_CERT_CHAIN_VALIDATOR_H
