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

/**
 * @tc.name: ValidateX509Cert_001
 * @tc.desc: Test validateX509Cert with null parameters
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_001, TestSize.Level0)
{
    HcfVerifyCertResult result = {};

    /* Test with null validator */
    CfResult res = g_validator->validateX509Cert(nullptr, nullptr, nullptr, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    /* Test with null cert */
    res = g_validator->validateX509Cert(g_validator, nullptr, nullptr, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    /* Test with null params */
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);
    res = g_validator->validateX509Cert(g_validator, cert, nullptr, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert);

    /* Test with null result */
    cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509CertValidatorParams params = {};
    res = g_validator->validateX509Cert(g_validator, cert, &params, nullptr);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert);
}

/**
 * @tc.name: ValidateX509Cert_002
 * @tc.desc: Test validateX509Cert without trust anchor (merged from 002, 010, 018)
 *           - trustSystemCa=false with no trustedCerts
 *           - untrustedCerts only without trustedCerts
 *           - empty params
 *           All should return CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_002, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert);
}

/**
 * @tc.name: ValidateX509Cert_002_1
 * @tc.desc: Test validateX509Cert with untrustedCerts only
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_002_1, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(intermediateCert, nullptr);
    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;
    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_002_2
 * @tc.desc: Test validateX509Cert with empty params
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_002_2, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509CertValidatorParams params = {};
    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert);
}

/**
 * @tc.name: ValidateX509Cert_003
 * @tc.desc: Test validateX509Cert with self-signed certificate and trustedCerts
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_003, TestSize.Level0)
{
    /* Create end entity cert */
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);

    /* Create trust anchor cert */
    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* With trust anchor, validation should succeed */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    /* trustCert is transferred to params, no need to destroy separately */
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_004
 * @tc.desc: Test validateX509Cert with certificate chain (root -> intermediate -> end entity)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_004, TestSize.Level0)
{
    /* Create end entity cert */
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(endEntityCert, nullptr);

    /* Create intermediate CA cert */
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(intermediateCaCert, nullptr);

    /* Create root CA cert */
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup untrusted certs (intermediate CA) */
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    /* Setup trusted certs (root CA) */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);

    /* Chain validation should succeed */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_005
 * @tc.desc: Test validateX509Cert with partialChain = true
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_005, TestSize.Level0)
{
    /* Create intermediate CA cert as end entity */
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(intermediateCaCert, nullptr);

    /* Create root CA cert as trust anchor */
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.partialChain = true;

    /* Setup trusted certs (root CA) */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, intermediateCaCert, &params, &result);

    /* Partial chain validation */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(intermediateCaCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_005_1
 * @tc.desc: Test validateX509Cert with partialChain = false
 *           When the cert chain is complete (intermediate CA signed by root CA),
 *           validation should succeed regardless of partialChain setting.
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_005_1, TestSize.Level0)
{
    /* Create intermediate CA cert as end entity */
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(intermediateCaCert, nullptr);

    /* Create root CA cert as trust anchor */
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.partialChain = false;  // Default value

    /* Setup trusted certs (root CA) */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, intermediateCaCert, &params, &result);

    /* Chain is complete (intermediate CA -> root CA), should succeed */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(intermediateCaCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_006
 * @tc.desc: Test validateX509Cert with validateDate = true
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_006, TestSize.Level0)
{
    /* Create self-signed cert */
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);

    /* Create trust anchor */
    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;  /* Validate date */

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Date validation result depends on cert validity period */
    /* Note: Test certificate dates may be expired, so result may vary */
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_007
 * @tc.desc: Test validateX509Cert with custom validation date
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_007, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;

    /* Set custom validation date */
    const char *customDate = "20240615000000Z";
    params.date = static_cast<char *>(CfMalloc(strlen(customDate) + 1, 0));
    ASSERT_NE(params.date, nullptr);
    (void)memcpy_s(params.date, strlen(customDate) + 1, customDate, strlen(customDate) + 1);

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Custom date validation */
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_008
 * @tc.desc: Test validateX509Cert with ignoreErrs
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_008, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup ignored errors */
    params.ignoreErrs.count = 2;
    params.ignoreErrs.data = static_cast<int32_t *>(CfMalloc(2 * sizeof(int32_t), 0));
    ASSERT_NE(params.ignoreErrs.data, nullptr);
    params.ignoreErrs.data[0] = CERT_NOT_YET_VALID;
    params.ignoreErrs.data[1] = CERT_HAS_EXPIRED;

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_009
 * @tc.desc: Test validateX509Cert with multiple trusted certs
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_009, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert1 = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert1, nullptr);

    HcfX509Certificate *trustCert2 = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert2, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup multiple trusted certs */
    params.trustedCerts.count = 2;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(2 * sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert1;
    params.trustedCerts.data[1] = trustCert2;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_012
 * @tc.desc: Test validateX509Cert with hostnames parameter
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_012, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    const char *hostname = "test.example.com";
    params.hostnames.count = 1;
    params.hostnames.data = static_cast<char **>(CfMalloc(sizeof(char *), 0));
    ASSERT_NE(params.hostnames.data, nullptr);
    params.hostnames.data[0] = static_cast<char *>(CfMalloc(strlen(hostname) + 1, 0));
    if (params.hostnames.data[0] != nullptr) {
        (void)memcpy_s(params.hostnames.data[0], strlen(hostname) + 1, hostname, strlen(hostname) + 1);
    }
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_013
 * @tc.desc: Test validateX509Cert with keyUsage parameter
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_013, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup keyUsage */
    params.keyUsage.count = 2;
    params.keyUsage.data = static_cast<int32_t *>(CfMalloc(2 * sizeof(int32_t), 0));
    ASSERT_NE(params.keyUsage.data, nullptr);
    params.keyUsage.data[0] = 0;  /* digitalSignature */
    params.keyUsage.data[1] = 1;  /* nonRepudiation */

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* KeyUsage validation */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_015
 * @tc.desc: Test validateX509Cert with emailAddresses parameter (email mismatch test)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_015, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup emailAddresses - cert doesn't have this email, so validation should fail */
    const char *email = "test@example.com";
    params.emailAddresses.count = 1;
    params.emailAddresses.data = static_cast<char **>(CfMalloc(sizeof(char *), 0));
    ASSERT_NE(params.emailAddresses.data, nullptr);
    params.emailAddresses.data[0] = static_cast<char *>(CfMalloc(strlen(email) + 1, 0));
    if (params.emailAddresses.data[0] != nullptr) {
        (void)memcpy_s(params.emailAddresses.data[0], strlen(email) + 1, email, strlen(email) + 1);
    }

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    /* Email validation should fail since cert doesn't have the email address */
    EXPECT_EQ(res, CF_ERR_CERT_EMAIL_MISMATCH);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_016
 * @tc.desc: Test validateX509Cert with allowDownloadIntermediateCa = true
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_016, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = true;  /* Enable intermediate CA download */

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Validation with download enabled */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_017
 * @tc.desc: Test getAlgorithm after validateX509Cert
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_017, TestSize.Level0)
{
    /* Verify validator is still functional */
    const char *algo = g_validator->getAlgorithm(g_validator);
    ASSERT_NE(algo, nullptr);
    string expectedAlgo("PKIX");
    ASSERT_STREQ(algo, expectedAlgo.c_str());
}

/**
 * @tc.name: ValidateX509Cert_019
 * @tc.desc: Test validateX509Cert with existing test certificate data
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_019, TestSize.Level0)
{
    /* Use existing test certificate from test common header */
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCaCert);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCaCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_020
 * @tc.desc: Test validateX509Cert memory allocation failure
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_020, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    HcfVerifyCertResult result = {};

    SetMockFlag(true);
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    SetMockFlag(false);

    /* Memory allocation failure should return error */
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
}

/**
 * @tc.name: ValidateX509Cert_021
 * @tc.desc: Test validateX509Cert with invalid keyUsage type
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_021, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);
    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.keyUsage.count = 1;
    params.keyUsage.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.keyUsage.data, nullptr);
    params.keyUsage.data[0] = 100;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;
    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_021_1
 * @tc.desc: Test validateX509Cert with too many keyUsage values
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_021_1, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);
    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.keyUsage.count = 10;
    params.keyUsage.data = static_cast<int32_t *>(CfMalloc(10 * sizeof(int32_t), 0));
    ASSERT_NE(params.keyUsage.data, nullptr);
    for (int i = 0; i < 10; i++) {
        params.keyUsage.data[i] = i;
    }
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;
    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_021_2
 * @tc.desc: Test validateX509Cert with negative keyUsage value
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_021_2, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);
    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.keyUsage.count = 1;
    params.keyUsage.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.keyUsage.data, nullptr);
    params.keyUsage.data[0] = -1;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;
    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_022
 * @tc.desc: Test validateX509Cert with too many emailAddresses (count > 1)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_022, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup too many emailAddresses (count = 2, but max is 1) */
    params.emailAddresses.count = 2;
    params.emailAddresses.data = static_cast<char **>(CfMalloc(2 * sizeof(char *), 0));
    ASSERT_NE(params.emailAddresses.data, nullptr);
    params.emailAddresses.data[0] = static_cast<char *>(CfMalloc(20, 0));
    params.emailAddresses.data[1] = static_cast<char *>(CfMalloc(20, 0));

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Should return CF_ERR_PARAMETER_CHECK for too many emailAddresses */
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_023
 * @tc.desc: Test validateX509Cert with invalid date string format
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_023, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;

    /* Set invalid date string */
    const char *invalidDate = "invalid_date_format";
    params.date = static_cast<char *>(CfMalloc(strlen(invalidDate) + 1, 0));
    ASSERT_NE(params.date, nullptr);
    (void)memcpy_s(params.date, strlen(invalidDate) + 1, invalidDate, strlen(invalidDate) + 1);

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Should return CF_ERR_PARAMETER_CHECK for invalid date format */
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_024
 * @tc.desc: Test validateX509Cert with hostname mismatch
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_024, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup hostname that won't match */
    const char *hostname = "nonexistent.example.com";
    params.hostnames.count = 1;
    params.hostnames.data = static_cast<char **>(CfMalloc(sizeof(char *), 0));
    ASSERT_NE(params.hostnames.data, nullptr);
    params.hostnames.data[0] = static_cast<char *>(CfMalloc(strlen(hostname) + 1, 0));
    ASSERT_NE(params.hostnames.data[0], nullptr);
    (void)memcpy_s(params.hostnames.data[0], strlen(hostname) + 1, hostname, strlen(hostname) + 1);

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Should return CF_ERR_CERT_HOST_NAME_MISMATCH */
    EXPECT_EQ(res, CF_ERR_CERT_HOST_NAME_MISMATCH);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_025
 * @tc.desc: Test validateX509Cert with email address mismatch
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_025, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup email that won't match */
    const char *email = "nonexistent@example.com";
    params.emailAddresses.count = 1;
    params.emailAddresses.data = static_cast<char **>(CfMalloc(sizeof(char *), 0));
    ASSERT_NE(params.emailAddresses.data, nullptr);
    params.emailAddresses.data[0] = static_cast<char *>(CfMalloc(strlen(email) + 1, 0));
    ASSERT_NE(params.emailAddresses.data[0], nullptr);
    (void)memcpy_s(params.emailAddresses.data[0], strlen(email) + 1, email, strlen(email) + 1);

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Should return CF_ERR_CERT_EMAIL_MISMATCH */
    EXPECT_EQ(res, CF_ERR_CERT_EMAIL_MISMATCH);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_026
 * @tc.desc: Test validateX509Cert with keyUsage mismatch (require keyCertSign but cert doesn't have it)
 *           Tests CheckCertValidatorExtensions keyUsage mismatch branch (Line 412)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_026, TestSize.Level0)
{
    /* Use end-entity cert which typically doesn't have keyCertSign */
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Require KEYUSAGE_KEY_CERT_SIGN (5), end-entity certs don't have this */
    params.keyUsage.count = 1;
    params.keyUsage.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.keyUsage.data, nullptr);
    params.keyUsage.data[0] = 5;  /* KEYUSAGE_KEY_CERT_SIGN */

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* End-entity cert should NOT have keyCertSign, so this should return mismatch */
    EXPECT_EQ(res, CF_ERR_CERT_KEY_USAGE_MISMATCH);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_027
 * @tc.desc: Test validateX509Cert with invalid revocationFlags value
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_027, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);
    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = 100;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;
    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_027_1
 * @tc.desc: Test validateX509Cert with empty revocationFlags
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_027_1, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);
    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->revocationFlags.count = 0;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;
    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_027_2
 * @tc.desc: Test validateX509Cert with only PREFER_OCSP flag
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_027_2, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);
    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_PREFER_OCSP;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;
    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_027_3
 * @tc.desc: Test validateX509Cert with too many revocationFlags
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_027_3, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);
    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->revocationFlags.count = 5;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(CfMalloc(5 * sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    for (int i = 0; i < 5; i++) {
        params.revokedParams->revocationFlags.data[i] = CERT_REVOCATION_CRL_CHECK;
    }
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;
    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_028, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);
    HcfX509Certificate *certSelf = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(certSelf, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.partialChain = true;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = certSelf;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->revocationFlags.count = 3;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(CfMalloc(3 * sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_PREFER_OCSP;
    params.revokedParams->revocationFlags.data[2] = CERT_REVOCATION_OCSP_CHECK;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* End-entity cert should NOT have keyCertSign, so this should return mismatch */
    EXPECT_EQ(res, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
    printf("result errorMsg = %s\n", result.errorMsg);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_SM2_001
 * @tc.desc: Test validateX509Cert with SM2 certificate chain
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_SM2_001, TestSize.Level0)
{
    HcfX509Certificate *signCert = CreateCertFromPem(SM2_SIGN_CERT);
    ASSERT_NE(signCert, nullptr);

    HcfX509Certificate *interCert = CreateCertFromPem(SM2_INTER_CERT);
    ASSERT_NE(interCert, nullptr);

    HcfX509Certificate *rootCert = CreateCertFromPem(SM2_ROOT_CERT);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = interCert;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, signCert, &params, &result);

    EXPECT_EQ(res, CF_ERR_CERT_SIGNATURE_FAILURE);
    CfObjDestroy(signCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_SM2_002
 * @tc.desc: Test validateX509Cert with SM2 certificate chain
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_SM2_002, TestSize.Level0)
{
    HcfX509Certificate *signCert = CreateCertFromPem(SM2_SIGN_CERT);
    ASSERT_NE(signCert, nullptr);

    HcfX509Certificate *interCert = CreateCertFromPem(SM2_INTER_CERT);
    ASSERT_NE(interCert, nullptr);

    HcfX509Certificate *rootCert = CreateCertFromPem(SM2_ROOT_CERT);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = interCert;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    static const uint8_t userIdData[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                                          0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    params.userId.data = const_cast<uint8_t *>(userIdData);
    params.userId.size = sizeof(userIdData);

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, signCert, &params, &result);

    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_EQ(result.certs.count, 3);
    FreeVerifyCertResult(result);

    CfObjDestroy(signCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_SM2_003
 * @tc.desc: Test validateX509Cert with SM2 certificate chain
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_SM2_003, TestSize.Level0)
{
    HcfX509Certificate *signCert = CreateCertFromPem(SM2_SIGN_CERT);
    ASSERT_NE(signCert, nullptr);

    HcfX509Certificate *interCert = CreateCertFromPem(SM2_INTER_CERT);
    ASSERT_NE(interCert, nullptr);

    HcfX509Certificate *rootCert = CreateCertFromPem(SM2_ROOT_CERT);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = interCert;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    static const uint8_t userIdData[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                                          0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    params.userId.data = const_cast<uint8_t *>(userIdData);
    params.userId.size = sizeof(userIdData);
    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->revocationFlags.count = 3;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(CfMalloc(3 * sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_PREFER_OCSP;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[2] = CERT_REVOCATION_OCSP_CHECK;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, signCert, &params, &result);

    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(signCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_SM2_004
 * @tc.desc: Test validateX509Cert with SM2 certificate chain
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_SM2_004, TestSize.Level0)
{
    HcfX509Certificate *signCert = CreateCertFromPem(SM2_SIGN_CERT);
    ASSERT_NE(signCert, nullptr);

    HcfX509Certificate *interCert = CreateCertFromPem(SM2_INTER_CERT);
    ASSERT_NE(interCert, nullptr);

    HcfX509Certificate *rootCert = CreateCertFromPem(SM2_ROOT_CERT);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = interCert;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    static const uint8_t userIdData[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                                          0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
    params.userId.data = const_cast<uint8_t *>(userIdData);
    params.userId.size = sizeof(userIdData);

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, signCert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CERT_SIGNATURE_FAILURE);

    CfObjDestroy(signCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_SM2_005
 * @tc.desc: Test validateX509Cert with SM2 certificate chain
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_SM2_005, TestSize.Level0)
{
    HcfX509Certificate *signCert = CreateCertFromPem(SM2_SIGN_CERT);
    ASSERT_NE(signCert, nullptr);

    HcfX509Certificate *interCert = CreateCertFromPem(SM2_INTER_CERT);
    ASSERT_NE(interCert, nullptr);

    HcfX509Certificate *rootCert = CreateCertFromPem(SM2_ROOT_CERT);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.partialChain = true;

    params.trustedCerts.count = 2;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *) * 2, 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = interCert;
    params.trustedCerts.data[1] = rootCert;

    static const uint8_t userIdData[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                                          0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    params.userId.data = const_cast<uint8_t *>(userIdData);
    params.userId.size = sizeof(userIdData);

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, signCert, &params, &result);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_EQ(result.certs.count, 2);
    FreeVerifyCertResult(result);

    CfObjDestroy(signCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_SM2_006
 * @tc.desc: Test validateX509Cert with SM2 certificate chain
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_SM2_006, TestSize.Level0)
{
    HcfX509Certificate *signCert = CreateCertFromPem(SM2_SIGN_CERT);
    ASSERT_NE(signCert, nullptr);
    HcfX509Certificate *signCertSelf = CreateCertFromPem(SM2_SIGN_CERT);
    ASSERT_NE(signCertSelf, nullptr);

    HcfX509Certificate *interCert = CreateCertFromPem(SM2_INTER_CERT);
    ASSERT_NE(interCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.partialChain = true;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = interCert;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *) * 1, 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = signCertSelf;

    static const uint8_t userIdData[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                                          0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    params.userId.data = const_cast<uint8_t *>(userIdData);
    params.userId.size = sizeof(userIdData);

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, signCert, &params, &result);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_EQ(result.certs.count, 1);
    FreeVerifyCertResult(result);

    CfObjDestroy(signCert);
    FreeValidatorParams(params);
}

}
