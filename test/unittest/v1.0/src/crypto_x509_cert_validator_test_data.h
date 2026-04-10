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

#ifndef CRYPTO_X509_CERT_VALIDATOR_TEST_DATA_H
#define CRYPTO_X509_CERT_VALIDATOR_TEST_DATA_H

#include <cstdint>
#include <cstddef>
#include <gtest/gtest.h>
#include <securec.h>
#include <string>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "cert_chain_validator.h"
#include "cf_blob.h"
#include "cf_log.h"
#include "cf_mock.h"
#include "cf_result.h"
#include "crypto_x509_test_common.h"
#include "memory_mock.h"
#include "x509_certificate.h"
#include "crypto_x509_cert_chain_data_pem_added.h"
#include "crypto_x509_cert_chain_data_pem_ex.h"
#include "crypto_x509_cert_validator_test_data.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Basic test certificates */
extern const char *TEST_ROOT_CA_CERT;
extern const char *TEST_INTERMEDIATE_CA_CERT;
extern const char *TEST_END_ENTITY_CERT;
extern const char *TEST_SELF_SIGNED_CERT;
extern const char *TEST_EXPIRED_CERT;
extern const char *TEST_NOT_YET_VALID_CERT;
extern const char *TEST_CRITICAL_EXT_CERT;
extern const char *TEST_SELF_SIGNED_UNTRUSTED_CERT;
extern const char *INTERMEDIATE_NO_KEY_CERT_SIGN_CERT;
extern const char *EE_BY_INTERMEDIATE_NO_KEY_CERT_SIGN_CERT;
extern const char *CORRUPTED_SIGNATURE_INTERMEDIATE_CA_CERT;
extern const char *EMAIL_TEST_CERT;

/* AIA test certificates */
extern const char *TEST_AIA_CERT;
extern const char *TEST_END_ENTITY_AIA_CERT;

/* CDP test certificates */
extern const char *TEST_ROOT_CA_FOR_CDP;
extern const char *TEST_INTERMEDIATE_CA_WITH_CDP;
extern const char *TEST_END_ENTITY_FOR_CDP;

/* OCSP test certificates */
extern const char *OCSP_TEST_ROOT_CA;
extern const char *OCSP_TEST_INTERMEDIATE_CA;
extern const char *OCSP_TEST_EE_VALID_URL;
extern const char *OCSP_TEST_EE_INVALID_URL;
extern const char *OCSP_TEST_SIGNER;

/* OCSP test responses */
extern const uint8_t OCSP_TEST_RESP_GOOD[1447];
extern const uint8_t OCSP_TEST_RESP_REVOKED[1464];
extern const uint8_t OCSP_TEST_RESP_UNKNOWN[1447];

/* OCSP response sizes */
extern const size_t OCSP_TEST_RESP_GOOD_SIZE;
extern const size_t OCSP_TEST_RESP_REVOKED_SIZE;
extern const size_t OCSP_TEST_RESP_UNKNOWN_SIZE;

/* Real-world test certificate */
extern const char *REAL_WORLD_CERT;
extern const char *REAL_WORLD_CERT_ISSUER;
extern const char *GLOBALSIGN_ROOT_CA_R3;

/* SM2 test certificates */
extern const char *SM2_SIGN_CERT;
extern const char *SM2_INTER_CERT;
extern const char *SM2_ROOT_CERT;

HcfX509Certificate *CreateCertFromPem(const char *pemCert);
void FreeVerifyCertResult(HcfVerifyCertResult &result);
void FreeValidatorParams(HcfX509CertValidatorParams &params);
void FreeValidatorParamsWithOcspData(HcfX509CertValidatorParams &params);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_X509_CERT_VALIDATOR_TEST_DATA_H */