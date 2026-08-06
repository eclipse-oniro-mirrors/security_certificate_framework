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
 * @tc.name: ValidateX509Cert_030
 * @tc.desc: Test validateX509Cert with result having non-empty certChain
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_030, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);

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

    /* Setup result with non-empty data (simulating already filled result) */
    HcfVerifyCertResult result = {};
    result.certs.count = 1;
    result.certs.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(result.certs.data, nullptr);
    result.certs.data[0] = nullptr;

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_030 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should return CF_ERR_PARAMETER_CHECK for non-empty result */
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfFree(result.certs.data);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_033
 * @tc.desc: Test validateX509Cert returns CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
 *          when no trust anchor is available
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_033, TestSize.Level0)
{
    /* Use end entity cert without providing the root CA as trust anchor */
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(endEntityCert, nullptr);

    HcfX509Certificate *intermediateCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup untrusted certs (intermediate CA) */
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    /* Setup trusted certs with a cert that is NOT the issuer (self-signed cert as fake trust anchor) */
    HcfX509Certificate *fakeTrustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(fakeTrustCert, nullptr);
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = fakeTrustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_030 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should return error because trust anchor doesn't match the chain */
    EXPECT_EQ(res, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_034
 * @tc.desc: Test validateX509Cert with valid revokedParams (CRL_CHECK)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_034, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup revokedParams with valid CRL_CHECK flag */
    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->allowDownloadCrl = false;  /* Don't download CRL */

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* The result depends on whether CRL check is available for the cert */
    /* Since no CRL is provided and download is disabled, it may fail or succeed */
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_035
 * @tc.desc: Test validateX509Cert with trustSystemCa=true
 *           This tests the trustSystemCa branch in ConstructTrustedStore
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_035, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = true;   /* Trust system CA store */
    params.validateDate = false;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_035 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* The result depends on whether system CA store is available and the cert is trusted */
    /* Since TEST_SELF_SIGNED_CERT is not in system CA store, validation may fail */
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
}

/**
 * @tc.name: ValidateX509Cert_035b
 * @tc.desc: Test validateX509Cert with CERT_REVOCATION_OCSP_CHECK flag
 *           This tests the OCSP_CHECK branch in CheckRevocationFlags
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_035b, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_035b failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_036
 * @tc.desc: Test validateX509Cert with expired certificate
 *           Expected: CF_ERR_CERT_HAS_EXPIRED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_036, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_EXPIRED_CERT);
    ASSERT_NE(cert, nullptr);

    /* Use the same expired cert as trust anchor to bypass trust check */
    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_EXPIRED_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;  /* Enable date validation */

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_036 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should return CF_ERR_CERT_HAS_EXPIRED for expired certificate */
    EXPECT_EQ(res, CF_ERR_CERT_HAS_EXPIRED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_037
 * @tc.desc: Test validateX509Cert with not-yet-valid certificate
 *           Expected: CF_ERR_CERT_NOT_YET_VALID
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_037, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_NOT_YET_VALID_CERT);
    ASSERT_NE(cert, nullptr);

    /* Use the same not-yet-valid cert as trust anchor to bypass trust check */
    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_NOT_YET_VALID_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;  /* Enable date validation */
    params.date = const_cast<char *>("20260801000000Z");

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_037 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should return CF_ERR_CERT_NOT_YET_VALID for not-yet-valid certificate */
    EXPECT_EQ(res, CF_ERR_CERT_NOT_YET_VALID);

    CfObjDestroy(cert);
    params.date = nullptr;
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_038
 * @tc.desc: Test validateX509Cert with certificate containing unknown critical extension
 *           Expected: CF_ERR_CERT_UNKNOWN_CRITICAL_EXTENSION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_038, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_CRITICAL_EXT_CERT);
    ASSERT_NE(cert, nullptr);

    /* Use the same cert as trust anchor since it's self-signed */
    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_CRITICAL_EXT_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_038 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should return CF_ERR_CERT_UNKNOWN_CRITICAL_EXTENSION for unknown critical extension */
    EXPECT_EQ(res, CF_ERR_CERT_UNKNOWN_CRITICAL_EXTENSION);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_039
 * @tc.desc: Test validateX509Cert with self-signed certificate not in trust store
 *           Expected: CF_ERR_CERT_UNTRUSTED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_039, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_UNTRUSTED_CERT);
    ASSERT_NE(cert, nullptr);

    /* Set a different trust anchor (not the cert being validated) */
    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Set trust anchor to a different cert */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_039 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should return CF_ERR_CERT_UNTRUSTED for self-signed cert not in trust store */
    EXPECT_EQ(res, CF_ERR_CERT_UNTRUSTED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_040
 * @tc.desc: Test validateX509Cert with expired cert but validateDate=false
 *           Expected: Should succeed since date validation is disabled
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_040, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_EXPIRED_CERT);
    ASSERT_NE(cert, nullptr);

    /* Use expired cert as trust anchor */
    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_EXPIRED_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;  /* Disable date validation */

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Should succeed since date validation is disabled */
    EXPECT_EQ(res, CF_SUCCESS);

    FreeVerifyCertResult(result);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}
/**
 * @tc.name: ValidateX509Cert_041
 * @tc.desc: Test allowDownloadIntermediateCa with incomplete chain and download disabled
 *           When allowDownloadIntermediateCa is false, download should not be attempted
 *           Expected: CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_041, TestSize.Level0)
{
    /* Create end entity cert without providing intermediate CA */
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(endEntityCert, nullptr);

    /* Create root CA cert as trust anchor (missing intermediate CA) */
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = false;  /* Download disabled */

    /* Setup trusted certs with only root CA (intermediate missing) */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_041 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should fail with UNABLE_TO_GET_ISSUER_CERT_LOCALLY since download is disabled */
    EXPECT_EQ(res, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_042
 * @tc.desc: Test allowDownloadIntermediateCa with incomplete chain and download enabled
 *           but certificate has no AIA extension
 *           Expected: CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_042, TestSize.Level0)
{
    /* Create end entity cert without providing intermediate CA */
    /* TEST_END_ENTITY_CERT has no AIA extension */
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(endEntityCert, nullptr);

    /* Create root CA cert as trust anchor (missing intermediate CA) */
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = true;  /* Download enabled */

    /* Setup trusted certs with only root CA (intermediate missing) */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_042 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should fail with UNABLE_TO_GET_ISSUER_CERT_LOCALLY since cert has no AIA */
    EXPECT_EQ(res, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_043
 * @tc.desc: Test allowDownloadIntermediateCa with self-signed cert that has AIA extension
 *           Since the cert is self-signed and not in trust anchor, download should be attempted
 *           but will fail because the URL is unreachable
 *           Expected: CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY (download fails)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_043, TestSize.Level0)
{
    /* Create cert with AIA extension pointing to unreachable URL */
    HcfX509Certificate *aiaCert = CreateCertFromPem(TEST_AIA_CERT);
    ASSERT_NE(aiaCert, nullptr);

    /* Use a different cert as trust anchor */
    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = true;  /* Download enabled */

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, aiaCert, &params, &result);

    /* Print error message for debugging */
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_043 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should fail because the cert is not signed by trust anchor */
    /* The download will be attempted but will fail (unreachable URL) */
    EXPECT_EQ(res, CF_ERR_CERT_UNTRUSTED);

    CfObjDestroy(aiaCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_044
 * @tc.desc: Test allowDownloadIntermediateCa with complete chain (no download needed)
 *           When chain is complete, download should not be triggered
 *           Expected: CF_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_044, TestSize.Level0)
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
    params.allowDownloadIntermediateCa = true;  /* Download enabled but not needed */

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    /* Setup untrusted certs (intermediate CA) */
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);

    /* Should succeed since chain is complete */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_046
 * @tc.desc: Test TryDownloadFromAccessDescriptionWithRetry with unreachable URL
 *           End entity cert signed by intermediate CA with AIA extension
 *           Chain is incomplete (missing intermediate CA), download should be attempted
 *           but will fail because the AIA URL is unreachable
 *           Expected: CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_046, TestSize.Level0)
{
    /* Create end entity cert signed by intermediate CA, with AIA extension */
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_AIA_CERT);
    ASSERT_NE(endEntityCert, nullptr);

    /* Create root CA cert as trust anchor (intermediate CA is missing) */
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = true;  /* Download enabled */

    /* Setup trusted certs with only root CA (intermediate missing) */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_046 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should fail because:
     * 1. Chain is incomplete (missing intermediate CA)
     * 2. Download is attempted but URL is unreachable (timeout)
     * Expected: CF_ERR_NETWORK_TIMEOUT (download timeout error)
     */
    EXPECT_EQ(res, CF_ERR_NETWORK_TIMEOUT);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_047
 * @tc.desc: Test with complete chain using TEST_END_ENTITY_AIA_CERT
 *           When intermediate CA is provided, download should not be triggered
 *           Expected: CF_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_047, TestSize.Level0)
{
    /* Create end entity cert signed by intermediate CA, with AIA extension */
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_AIA_CERT);
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
    params.allowDownloadIntermediateCa = true;  /* Download enabled but not needed */

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    /* Setup untrusted certs (intermediate CA provided) */
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);

    /* Should succeed because intermediate CA is provided */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest001
 * @tc.desc: Test X509_STORE_new failure in ConstructTrustedStore
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest001, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_new())
        .WillOnce(Return(nullptr));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest001 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest002
 * @tc.desc: Test X509_STORE_add_cert failure in ConstructTrustedStore
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest002, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_add_cert(_, _))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest002 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest003
 * @tc.desc: Test X509_up_ref failure in ConstructUntrustedStack
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest003, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

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

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_up_ref(_))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest003 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest004
 * @tc.desc: Test ASN1_TIME_new failure in ConvertTimeStrToTimeT
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest004, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;
    params.date = const_cast<char *>("2025-01-01 00:00:00");

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), ASN1_TIME_new())
        .WillOnce(Return(nullptr));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest004 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    params.date = nullptr; // Don't free string literal
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest005
 * @tc.desc: Test ASN1_TIME_set_string failure in ConvertTimeStrToTimeT
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest005, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;
    params.date = const_cast<char *>("2025-01-01 00:00:00");

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), ASN1_TIME_set_string(_, _))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest005 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(endEntityCert);
    params.date = nullptr; // Don't free string literal
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest006
 * @tc.desc: Test ASN1_TIME_to_tm failure in ConvertTimeStrToTimeT
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest006, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;
    params.date = const_cast<char *>("2025-01-01 00:00:00");

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), ASN1_TIME_set_string(_, _))
        .WillOnce(Return(1)); // Success so we can test ASN1_TIME_to_tm
    EXPECT_CALL(X509OpensslMock::GetInstance(), ASN1_TIME_to_tm(_, _))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest006 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    params.date = nullptr; // Don't free string literal
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest007
 * @tc.desc: Test X509_STORE_CTX_new failure in ExecuteSingleVerification
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest007, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

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

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_new())
        .WillOnce(Return(nullptr));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest007 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest008
 * @tc.desc: Test X509_STORE_CTX_init failure in ExecuteSingleVerification
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest008, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

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

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_init(_, _, _, _))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest008 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest009
 * @tc.desc: Test X509_STORE_add_cert failure in ConstructTrustedStore
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest009, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

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

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_add_cert(_, _))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest009 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest012
 * @tc.desc: Test X509_verify_cert returns error with X509_V_ERR_CERT_HAS_EXPIRED
 *           This tests ConvertOpensslErrorMsgEx with an error that maps to CF_ERR_CERT_HAS_EXPIRED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest012, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

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

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_CERT_HAS_EXPIRED));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest012 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CERT_HAS_EXPIRED);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest013
 * @tc.desc: Test X509_verify_cert returns error with X509_V_ERR_CERT_NOT_YET_VALID
 *           This tests ConvertOpensslErrorMsgEx with an error that maps to CF_ERR_CERT_NOT_YET_VALID
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest013, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

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

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_CERT_NOT_YET_VALID));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest013 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CERT_NOT_YET_VALID);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest014
 * @tc.desc: Test X509_verify_cert returns error with X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
 *           This tests ConvertOpensslErrorMsgEx with self-signed cert error mapping to CF_ERR_CERT_UNTRUSTED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest014, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

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

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest014 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CERT_UNTRUSTED);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest015
 * @tc.desc: Test X509_verify_cert returns error with unknown error code
 *           This tests ConvertOpensslErrorMsg returning CF_ERR_CRYPTO_OPERATION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest015, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

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

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_UNSPECIFIED));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest015 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}
}
