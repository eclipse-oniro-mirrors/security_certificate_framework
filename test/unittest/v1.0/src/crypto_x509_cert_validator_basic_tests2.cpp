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

#include "crypto_x509_cert_validator_test_common.h"

using namespace std;
using namespace testing::ext;
using namespace CFMock;
using ::testing::Return;
using ::testing::_;
using ::testing::Mock;
using ::testing::Invoke;
using ::testing::WithoutArgs;

namespace {

HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_basic_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(REAL_WORLD_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *issuer = CreateCertFromPem(REAL_WORLD_CERT_ISSUER);
    ASSERT_NE(issuer, nullptr);
    HcfX509Certificate *root = CreateCertFromPem(GLOBALSIGN_ROOT_CA_R3);
    ASSERT_NE(root, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    HcfX509Certificate *certs[1] = { root };
    params.trustedCerts.data = certs;
    params.trustedCerts.count = 1;

    HcfX509Certificate *untrustedCerts[1] = { issuer };
    params.untrustedCerts.data = untrustedCerts;
    params.untrustedCerts.count = 1;

    HcfVerifyCertResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    CF_LOG_I("ValidateX509Cert_basic_001: result=%d, errorMsg=%s",
             res, result.errorMsg ? result.errorMsg : "null");

    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_EQ(result.certs.count, 3);

    CfObjDestroy(cert);
    CfObjDestroy(issuer);
    CfObjDestroy(root);
    FreeVerifyCertResult(result);
}

HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_basic_ignore_cert_expired, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(REAL_WORLD_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *issuer = CreateCertFromPem(REAL_WORLD_CERT_ISSUER);
    ASSERT_NE(issuer, nullptr);
    HcfX509Certificate *root = CreateCertFromPem(GLOBALSIGN_ROOT_CA_R3);
    ASSERT_NE(root, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;
    params.date = const_cast<char *>("20800409120000Z");

    HcfX509Certificate *certs[1] = { root };
    params.trustedCerts.data = certs;
    params.trustedCerts.count = 1;

    HcfX509Certificate *untrustedCerts[1] = { issuer };
    params.untrustedCerts.data = untrustedCerts;
    params.untrustedCerts.count = 1;

    HcfVerifyCertResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    CF_LOG_I("ValidateX509Cert_basic_ignore_cert_expired: result=%d, errorMsg=%s",
             res, result.errorMsg ? result.errorMsg : "null");

    EXPECT_EQ(res, CF_ERR_CERT_HAS_EXPIRED);

    int32_t ignoreErrs[1] = { CERT_HAS_EXPIRED };
    params.ignoreErrs.data = ignoreErrs;
    params.ignoreErrs.count = 1;

    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    CF_LOG_I("ValidateX509Cert_basic_ignore_cert_expired: result=%d, errorMsg=%s",
             res, result.errorMsg ? result.errorMsg : "null");

    EXPECT_EQ(res, CF_SUCCESS);

    CfObjDestroy(cert);
    CfObjDestroy(issuer);
    CfObjDestroy(root);
    FreeVerifyCertResult(result);
}

HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_basic_ignore_cert_not_yet_valid, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(REAL_WORLD_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *issuer = CreateCertFromPem(REAL_WORLD_CERT_ISSUER);
    ASSERT_NE(issuer, nullptr);
    HcfX509Certificate *root = CreateCertFromPem(GLOBALSIGN_ROOT_CA_R3);
    ASSERT_NE(root, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;
    params.date = const_cast<char *>("20000409120000Z");

    HcfX509Certificate *certs[1] = { root };
    params.trustedCerts.data = certs;
    params.trustedCerts.count = 1;

    HcfX509Certificate *untrustedCerts[1] = { issuer };
    params.untrustedCerts.data = untrustedCerts;
    params.untrustedCerts.count = 1;

    HcfVerifyCertResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    CF_LOG_I("ValidateX509Cert_basic_ignore_cert_not_yet_valid: result=%d, errorMsg=%s",
             res, result.errorMsg ? result.errorMsg : "null");

    EXPECT_EQ(res, CF_ERR_CERT_NOT_YET_VALID);

    int32_t ignoreErrs[1] = { CERT_NOT_YET_VALID };
    params.ignoreErrs.data = ignoreErrs;
    params.ignoreErrs.count = 1;

    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    CF_LOG_I("ValidateX509Cert_basic_ignore_cert_not_yet_valid: result=%d, errorMsg=%s",
             res, result.errorMsg ? result.errorMsg : "null");

    EXPECT_EQ(res, CF_SUCCESS);

    CfObjDestroy(cert);
    CfObjDestroy(issuer);
    CfObjDestroy(root);
    FreeVerifyCertResult(result);
}

HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_basic_ignore_crl_not_find, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(REAL_WORLD_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *issuer = CreateCertFromPem(REAL_WORLD_CERT_ISSUER);
    ASSERT_NE(issuer, nullptr);
    HcfX509Certificate *root = CreateCertFromPem(GLOBALSIGN_ROOT_CA_R3);
    ASSERT_NE(root, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;
    HcfX509Certificate *certs[1] = { root };
    params.trustedCerts.data = certs;
    params.trustedCerts.count = 1;

    HcfX509Certificate *untrustedCerts[1] = { issuer };
    params.untrustedCerts.data = untrustedCerts;
    params.untrustedCerts.count = 1;

    HcfX509CertRevokedParams revokedParams = {};
    revokedParams.revocationFlags.count = 1;
    int32_t revocationFlags[2] = { CERT_REVOCATION_CRL_CHECK, CERT_REVOCATION_CHECK_ALL_CERT};
    revokedParams.revocationFlags.data = revocationFlags;
    params.revokedParams = &revokedParams;

    HcfVerifyCertResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    CF_LOG_I("ValidateX509Cert_basic_ignore_crl_not_find: result=%d, errorMsg=%s",
             res, result.errorMsg ? result.errorMsg : "null");

    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);

    int32_t ignoreErrs[1] = { CRL_NOT_FOUND };
    params.ignoreErrs.data = ignoreErrs;
    params.ignoreErrs.count = 1;

    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    CF_LOG_I("ValidateX509Cert_basic_ignore_crl_not_find: result=%d, errorMsg=%s",
             res, result.errorMsg ? result.errorMsg : "null");

    EXPECT_EQ(res, CF_SUCCESS);

    CfObjDestroy(cert);
    CfObjDestroy(issuer);
    CfObjDestroy(root);
    FreeVerifyCertResult(result);
}

HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_basic_ignore_ocsp_response_not_find, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(REAL_WORLD_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *issuer = CreateCertFromPem(REAL_WORLD_CERT_ISSUER);
    ASSERT_NE(issuer, nullptr);
    HcfX509Certificate *root = CreateCertFromPem(GLOBALSIGN_ROOT_CA_R3);
    ASSERT_NE(root, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;
    HcfX509Certificate *certs[1] = { root };
    params.trustedCerts.data = certs;
    params.trustedCerts.count = 1;

    HcfX509Certificate *untrustedCerts[1] = { issuer };
    params.untrustedCerts.data = untrustedCerts;
    params.untrustedCerts.count = 1;

    HcfX509CertRevokedParams revokedParams = {};
    revokedParams.revocationFlags.count = 1;
    int32_t revocationFlags[2] = { CERT_REVOCATION_OCSP_CHECK, CERT_REVOCATION_CHECK_ALL_CERT};
    revokedParams.revocationFlags.data = revocationFlags;
    params.revokedParams = &revokedParams;

    HcfVerifyCertResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    CF_LOG_I("ValidateX509Cert_basic_ignore_ocsp_response_not_find: result=%d, errorMsg=%s",
             res, result.errorMsg ? result.errorMsg : "null");

    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);

    int32_t ignoreErrs[1] = { OCSP_RESPONSE_NOT_FOUND };
    params.ignoreErrs.data = ignoreErrs;
    params.ignoreErrs.count = 1;

    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    CF_LOG_I("ValidateX509Cert_basic_ignore_ocsp_response_not_find: result=%d, errorMsg=%s",
             res, result.errorMsg ? result.errorMsg : "null");

    EXPECT_EQ(res, CF_SUCCESS);

    CfObjDestroy(cert);
    CfObjDestroy(issuer);
    CfObjDestroy(root);
    FreeVerifyCertResult(result);
}

HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_basic_ignore_empty, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(REAL_WORLD_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *issuer = CreateCertFromPem(REAL_WORLD_CERT_ISSUER);
    ASSERT_NE(issuer, nullptr);
    HcfX509Certificate *root = CreateCertFromPem(GLOBALSIGN_ROOT_CA_R3);
    ASSERT_NE(root, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;
    HcfX509Certificate *certs[1] = { root };
    params.trustedCerts.data = certs;
    params.trustedCerts.count = 1;

    HcfX509Certificate *untrustedCerts[1] = { issuer };
    params.untrustedCerts.data = untrustedCerts;
    params.untrustedCerts.count = 1;

    HcfX509CertRevokedParams revokedParams = {};
    revokedParams.revocationFlags.count = 1;
    int32_t revocationFlags[2] = { CERT_REVOCATION_OCSP_CHECK, CERT_REVOCATION_CHECK_ALL_CERT};
    revokedParams.revocationFlags.data = revocationFlags;
    params.revokedParams = &revokedParams;

    int32_t ignoreErrs[1] = { OCSP_RESPONSE_NOT_FOUND };
    params.ignoreErrs.data = ignoreErrs;
    params.ignoreErrs.count = 0;

    HcfVerifyCertResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    CF_LOG_I("ValidateX509Cert_basic_ignore_ocsp_response_not_find: result=%d, errorMsg=%s",
             res, result.errorMsg ? result.errorMsg : "null");

    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);

    CfObjDestroy(cert);
    CfObjDestroy(issuer);
    CfObjDestroy(root);
    FreeVerifyCertResult(result);
}

HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_basic_ignore_error_invalid_param, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(REAL_WORLD_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *issuer = CreateCertFromPem(REAL_WORLD_CERT_ISSUER);
    ASSERT_NE(issuer, nullptr);
    HcfX509Certificate *root = CreateCertFromPem(GLOBALSIGN_ROOT_CA_R3);
    ASSERT_NE(root, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    HcfX509Certificate *certs[1] = { root };
    params.trustedCerts.data = certs;
    params.trustedCerts.count = 1;

    HcfX509Certificate *untrustedCerts[1] = { issuer };
    params.untrustedCerts.data = untrustedCerts;
    params.untrustedCerts.count = 1;

    int32_t ignoreErrs[] = { CERT_NOT_YET_VALID, CERT_HAS_EXPIRED, CERT_UNKNOWN_CRITICAL_EXTENSION, CRL_NOT_FOUND,
        CRL_NOT_YET_VALID, CRL_HAS_EXPIRED, OCSP_RESPONSE_NOT_FOUND, NETWORK_TIMEOUT };
    params.ignoreErrs.data = ignoreErrs;
    params.ignoreErrs.count = (uint32_t)(sizeof(ignoreErrs) / sizeof(ignoreErrs[0]));

    HcfVerifyCertResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    CF_LOG_I("ValidateX509Cert_basic_ignore_ocsp_response_not_find: result=%d, errorMsg=%s",
             res, result.errorMsg ? result.errorMsg : "null");
    EXPECT_EQ(res, CF_SUCCESS);
    FreeVerifyCertResult(result);

    int32_t ignoreErrs2[] = { CERT_NOT_YET_VALID, CERT_HAS_EXPIRED, CERT_UNKNOWN_CRITICAL_EXTENSION, CRL_NOT_FOUND,
        CRL_NOT_YET_VALID, CRL_HAS_EXPIRED, OCSP_RESPONSE_NOT_FOUND, NETWORK_TIMEOUT, NETWORK_TIMEOUT };
    params.ignoreErrs.data = ignoreErrs2;
    params.ignoreErrs.count = (uint32_t)(sizeof(ignoreErrs2) / sizeof(ignoreErrs2[0]));
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    CF_LOG_I("ValidateX509Cert_basic_ignore_ocsp_response_not_find: result=%d, errorMsg=%s",
             res, result.errorMsg ? result.errorMsg : "null");
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    int32_t ignoreErrs3[] = { CERT_NOT_YET_VALID, CERT_HAS_EXPIRED, CERT_UNKNOWN_CRITICAL_EXTENSION, CRL_NOT_FOUND,
        CRL_NOT_YET_VALID, CRL_HAS_EXPIRED, OCSP_RESPONSE_NOT_FOUND, CF_ERR_PARAMETER_CHECK };
    params.ignoreErrs.data = ignoreErrs3;
    params.ignoreErrs.count = (uint32_t)(sizeof(ignoreErrs3) / sizeof(ignoreErrs3[0]));
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    CF_LOG_I("ValidateX509Cert_basic_ignore_ocsp_response_not_find: result=%d, errorMsg=%s",
             res, result.errorMsg ? result.errorMsg : "null");
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert);
    CfObjDestroy(issuer);
    CfObjDestroy(root);
}

}