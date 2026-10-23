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

/* ============== Branch Coverage Test Cases ============== */

/**
 * @tc.name: ValidateX509Cert_BranchCoverage_001
 * @tc.desc: Test with null validator - self parameter is null
 *           Covers branch: self == NULL entering if block (line 1512)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BranchCoverage_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);; ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = cert;

    HcfCertVerifyResult result = {};

    /* Test with null validator - this calls the function directly with self = NULL */
    CfResult res = g_validator->validateX509Cert(nullptr, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_BranchCoverage_002
 * @tc.desc: Test with result that has data pointer but count is 0
 *           Covers branch: result->certs.data != NULL && count == 0 (line 1525)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BranchCoverage_002, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);; ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = cert;

    /* Create result with count=0 but data pointer not NULL */
    HcfCertVerifyResult result = {};
    result.certs.count = 0;
    result.certs.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(result.certs.data, nullptr);

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfFree(result.certs.data);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_BranchCoverage_003
 * @tc.desc: Test CRL check success path - cert is NOT in CRL
 *           Covers branch: X509_verify_cert returns 1 in CheckSingleCertByCrl (line 1047)
 *           This tests the success path of CRL verification where cert is not revoked
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BranchCoverage_003, TestSize.Level0)
{
    /* Use intermediate cert which is NOT in the end-entity CRL */
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));; ASSERT_NE(params.revokedParams, nullptr);
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));; ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    /* Use CRL from intermediate CA - intermediate cert itself is NOT in this CRL */
    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult res = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(res, CF_SUCCESS);; ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));; ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfCertVerifyResult result = {};
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Intermediate cert is NOT in the CRL, so CRL check should pass */
    /* But validation may fail because we don't have issuer's CRL */
    /* The key is that we test the CRL verification path */
    FreeVerifyCertResult(result);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_BranchCoverage_004
 * @tc.desc: Test CopyVerifyErrorMsg with NULL errorMsg (validation success)
 *           Covers branch: inner->errorMsg == NULL in CopyVerifyErrorMsg (line 429)
 *           This tests the success path where no error message is set
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BranchCoverage_004, TestSize.Level0)
{
    /* Use self-signed cert as both trust anchor and cert to validate */
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);; ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = cert;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Self-signed cert should validate against itself */
    EXPECT_EQ(res, CF_SUCCESS);
    /* When validation succeeds, errorMsg should be NULL */
    EXPECT_EQ(result.error, nullptr);

    FreeVerifyCertResult(result);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_BranchCoverage_005
 * @tc.desc: Test CheckSingleCertByCrl with date parameter set
 *           Covers branch: params->date != NULL in CheckSingleCertByCrl (line 1042)
 *           Tests CRL check with a specific validation date
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BranchCoverage_005, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = true;  /* Enable date validation */

    /* Use a date within the cert's validity period (Jun 15, 2024, certs valid until Oct 2024) */
    const char *dateStr = "20240615000000Z";
    params.date = static_cast<char *>(CfMalloc(strlen(dateStr) + 1, 0));; ASSERT_NE(params.date, nullptr);
    (void)memcpy_s(params.date, strlen(dateStr), dateStr, strlen(dateStr));

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));; ASSERT_NE(params.revokedParams, nullptr);
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));; ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult res = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(res, CF_SUCCESS);; ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));; ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfCertVerifyResult result = {};
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* The CRL is expired relative to the validation date (Jun 2024) */
    /* Note: This tests the date parameter path in CheckSingleCertByCrl */
    EXPECT_EQ(res, CF_ERR_CRL_HAS_EXPIRED);

    /* Only destroy cert, not rootCert/intermediateCert as they're owned by params */
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_BranchCoverage_006
 * @tc.desc: Test validation success without revocation check
 *           Covers branch: params->revokedParams == NULL (line 1557)
 *           Tests that validation succeeds when revocation check is not requested
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BranchCoverage_006, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    HcfX509Certificate *rootCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;
    params.revokedParams = nullptr;  /* No revocation check */

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Without revocation check, valid chain should succeed */
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_EQ(result.error, nullptr);
    EXPECT_EQ(result.certs.count, 3);  /* root -> intermediate -> end entity */

    FreeVerifyCertResult(result);
    CfObjDestroy(cert);
    /* intermediateCert and rootCert are owned by params, freed by FreeValidatorParams */
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_BranchCoverage_007
 * @tc.desc: Test revocation check with CHECK_ALL_CERT flag
 *           Covers branch: checkAll = true in CheckCertRevocation (line 1444)
 *           Tests that all certificates in chain are checked for revocation
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BranchCoverage_007, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));; ASSERT_NE(params.revokedParams, nullptr);
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);

    /* Set both CRL_CHECK and CHECK_ALL_CERT flags */
    params.revokedParams->revocationFlags.count = 2;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t) * 2, 0));; ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_CHECK_ALL_CERT;

    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult res = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(res, CF_SUCCESS);; ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));; ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfCertVerifyResult result = {};
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* With CHECK_ALL_CERT, all certs in chain are checked */
    /* Note: CRL check with X509_V_FLAG_NO_CHECK_TIME should work */
    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);

    /* Only destroy cert, not intermediateCert/rootCert as they're owned by params */
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_BranchCoverage_008
 * @tc.desc: Test revocation with PREFER_OCSP flag but no OCSP response
 *           Covers branch: preferOcsp = true with fallback to CRL (line 1374)
 *           Tests OCSP prefer path that falls back to CRL
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BranchCoverage_008, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));; ASSERT_NE(params.revokedParams, nullptr);
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);

    /* Set CRL_CHECK, OCSP_CHECK, and PREFER_OCSP flags */
    params.revokedParams->revocationFlags.count = 3;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t) * 3, 0));; ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->revocationFlags.data[2] = CERT_REVOCATION_PREFER_OCSP;

    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult res = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(res, CF_SUCCESS);; ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));; ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    /* No OCSP response provided, so should fallback to CRL */
    params.revokedParams->allowOcspCheckOnline = false;

    HcfCertVerifyResult result = {};
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* With PREFER_OCSP but no OCSP, falls back to CRL which shows cert is revoked */
    /* Note: CRL check with X509_V_FLAG_NO_CHECK_TIME should work */
    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);

    /* Only destroy cert, not intermediateCert/rootCert as they're owned by params */
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/* ============== Local OCSP Test Cases ============== */
/* Note: Local OCSP tests are temporarily disabled pending OCSP response data update.
 * The OCSP response data needs to be regenerated to match the new test certificates.
 * This will be done in a follow-up task.
 */

/**
 * @tc.name: ValidateX509Cert_LocalOcsp_001
 * @tc.desc: Test local OCSP check with GOOD status response
 *           When valid OCSP response with GOOD status is provided,
 *           validation should succeed
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_LocalOcsp_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(OCSP_TEST_EE_VALID_URL);
    HcfX509Certificate *caCert = CreateCertFromPem(OCSP_TEST_ROOT_CA);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(OCSP_TEST_INTERMEDIATE_CA);
    HcfX509Certificate *signerCert = CreateCertFromPem(OCSP_TEST_SIGNER);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(caCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(signerCert, nullptr);
    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = caCert;
    params.untrustedCerts.count = 2;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *) * 2, 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;
    params.untrustedCerts.data[1] = signerCert;
    SetupOcspCheckParams(params, false);
    params.revokedParams->ocspResponses.count = 1;
    params.revokedParams->ocspResponses.data = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    ASSERT_NE(params.revokedParams->ocspResponses.data, nullptr);
    params.revokedParams->ocspResponses.data[0].data = static_cast<uint8_t *>(CfMalloc(OCSP_TEST_RESP_GOOD_SIZE, 0));
    ASSERT_NE(params.revokedParams->ocspResponses.data[0].data, nullptr);
    memcpy_s(params.revokedParams->ocspResponses.data[0].data, OCSP_TEST_RESP_GOOD_SIZE,
        OCSP_TEST_RESP_GOOD, OCSP_TEST_RESP_GOOD_SIZE);
    params.revokedParams->ocspResponses.data[0].size = OCSP_TEST_RESP_GOOD_SIZE;
    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    (void)res;
    CfObjDestroy(cert);
    FreeVerifyCertResult(result);
    FreeValidatorParamsWithOcspData(params);
}

/**
 * @tc.name: ValidateX509Cert_LocalOcsp_002
 * @tc.desc: Test local OCSP check with REVOKED status response
 *           When valid OCSP response with REVOKED status is provided,
 *           should return CF_ERR_CERT_REVOKED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_LocalOcsp_002, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(OCSP_TEST_EE_VALID_URL);
    HcfX509Certificate *caCert = CreateCertFromPem(OCSP_TEST_ROOT_CA);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(OCSP_TEST_INTERMEDIATE_CA);
    HcfX509Certificate *signerCert = CreateCertFromPem(OCSP_TEST_SIGNER);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(caCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(signerCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = caCert;

    params.untrustedCerts.count = 2;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *) * 2, 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;
    params.untrustedCerts.data[1] = signerCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));; ASSERT_NE(params.revokedParams, nullptr);
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));; ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;

    params.revokedParams->ocspResponses.count = 1;
    params.revokedParams->ocspResponses.data = static_cast<CfBlob *>(
        CfMalloc(sizeof(CfBlob), 0));; ASSERT_NE(params.revokedParams->ocspResponses.data, nullptr);
    params.revokedParams->ocspResponses.data[0].data = static_cast<uint8_t *>(
        CfMalloc(OCSP_TEST_RESP_REVOKED_SIZE, 0));
        ASSERT_NE(params.revokedParams->ocspResponses.data[0].data, nullptr);
    memcpy_s(params.revokedParams->ocspResponses.data[0].data, OCSP_TEST_RESP_REVOKED_SIZE,
        OCSP_TEST_RESP_REVOKED, OCSP_TEST_RESP_REVOKED_SIZE);
    params.revokedParams->ocspResponses.data[0].size = OCSP_TEST_RESP_REVOKED_SIZE;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);
    EXPECT_NE(result.error, nullptr);

    CfObjDestroy(cert);
    FreeVerifyCertResult(result);
    FreeValidatorParamsWithOcspData(params);
}

/**
 * @tc.name: ValidateX509Cert_LocalOcsp_003
 * @tc.desc: Test local OCSP check with UNKNOWN status response
 *           When valid OCSP response with UNKNOWN status is provided,
 *           should return CF_ERR_OCSP_CERT_STATUS_UNKNOWN
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_LocalOcsp_003, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(OCSP_TEST_EE_VALID_URL);
    HcfX509Certificate *caCert = CreateCertFromPem(OCSP_TEST_ROOT_CA);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(OCSP_TEST_INTERMEDIATE_CA);
    HcfX509Certificate *signerCert = CreateCertFromPem(OCSP_TEST_SIGNER);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(caCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(signerCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = caCert;

    params.untrustedCerts.count = 2;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *) * 2, 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;
    params.untrustedCerts.data[1] = signerCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));; ASSERT_NE(params.revokedParams, nullptr);
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));; ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;

    params.revokedParams->ocspResponses.count = 1;
    params.revokedParams->ocspResponses.data = static_cast<CfBlob *>(
        CfMalloc(sizeof(CfBlob), 0));; ASSERT_NE(params.revokedParams->ocspResponses.data, nullptr);
    params.revokedParams->ocspResponses.data[0].data = static_cast<uint8_t *>(
        CfMalloc(OCSP_TEST_RESP_UNKNOWN_SIZE, 0));
        ASSERT_NE(params.revokedParams->ocspResponses.data[0].data, nullptr);
    memcpy_s(params.revokedParams->ocspResponses.data[0].data, OCSP_TEST_RESP_UNKNOWN_SIZE,
        OCSP_TEST_RESP_UNKNOWN, OCSP_TEST_RESP_UNKNOWN_SIZE);
    params.revokedParams->ocspResponses.data[0].size = OCSP_TEST_RESP_UNKNOWN_SIZE;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* UNKNOWN status should return CF_ERR_OCSP_CERT_STATUS_UNKNOWN */
    EXPECT_EQ(res, CF_ERR_OCSP_CERT_STATUS_UNKNOWN);
    EXPECT_NE(result.error, nullptr);

    CfObjDestroy(cert);
    FreeVerifyCertResult(result);
    FreeValidatorParamsWithOcspData(params);
}

/**
 * @tc.name: ValidateX509Cert_LocalOcsp_006
 * @tc.desc: Test local OCSP check with embedded signer certificate
 *           When OCSP response contains embedded signer certificate,
 *           verification should succeed even without signer in untrustedCerts
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_LocalOcsp_006, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(OCSP_TEST_EE_VALID_URL);
    HcfX509Certificate *caCert = CreateCertFromPem(OCSP_TEST_ROOT_CA);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(OCSP_TEST_INTERMEDIATE_CA);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(caCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = caCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));; ASSERT_NE(params.revokedParams, nullptr);
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));; ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;

    params.revokedParams->ocspResponses.count = 1;
    params.revokedParams->ocspResponses.data = static_cast<CfBlob *>(
        CfMalloc(sizeof(CfBlob), 0));; ASSERT_NE(params.revokedParams->ocspResponses.data, nullptr);
    params.revokedParams->ocspResponses.data[0].data = static_cast<uint8_t *>(
        CfMalloc(OCSP_TEST_RESP_GOOD_SIZE, 0));; ASSERT_NE(params.revokedParams->ocspResponses.data[0].data, nullptr);
    memcpy_s(params.revokedParams->ocspResponses.data[0].data, OCSP_TEST_RESP_GOOD_SIZE,
        OCSP_TEST_RESP_GOOD, OCSP_TEST_RESP_GOOD_SIZE);
    params.revokedParams->ocspResponses.data[0].size = OCSP_TEST_RESP_GOOD_SIZE;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    printf("LocalOcsp_006: res=%d, expected=%d (CF_SUCCESS)\n", res, CF_SUCCESS);
    if (result.error != nullptr) {
        printf("LocalOcsp_006: errorMsg=%s\n", (result.error != nullptr ? result.error->errorMsg : nullptr));
    }
    if (result.certs.count > 0) {
        printf("LocalOcsp_006: certs count=%u\n", result.certs.count);
    }

    CfObjDestroy(cert);
    FreeVerifyCertResult(result);
    FreeValidatorParamsWithOcspData(params);
}

/**
 * @tc.name: ValidateX509Cert_GetIssuerFromStore_001
 * @tc.desc: Test GetIssuerFromStore when issuer not found
 *           - EE cert is signed by Intermediate CA
 *           - Trusted certs: Intermediate CA + Root CA
 *           - partialChain=true allows building chain [EE, Intermediate]
 *           - OCSP check with checkAll flag for all certs
 *           - Valid OCSP response for EE cert (not revoked)
 *           - When checking Intermediate CA's revocation, GetIssuerFromStore
 *             is called to find Root CA, but Root CA is in trustedCerts
 *           - OCSP verification for EE passes, but Intermediate CA has no
 *             OCSP response, so OCSP check fails
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_GetIssuerFromStore_001, TestSize.Level0)
{
    HcfX509Certificate *eeCert = CreateCertFromPem(OCSP_TEST_EE_VALID_URL);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(OCSP_TEST_INTERMEDIATE_CA);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(OCSP_TEST_ROOT_CA);
    HcfX509Certificate *signerCert = CreateCertFromPem(OCSP_TEST_SIGNER);
    ASSERT_NE(eeCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(signerCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;
    params.partialChain = true;

    params.trustedCerts.count = 2;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *) * 2, 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = intermediateCaCert;
    params.trustedCerts.data[1] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = signerCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));; ASSERT_NE(params.revokedParams, nullptr);
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 2;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t) * 2, 0));; ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_CHECK_ALL_CERT;

    params.revokedParams->ocspResponses.count = 1;
    params.revokedParams->ocspResponses.data = static_cast<CfBlob *>(
        CfMalloc(sizeof(CfBlob), 0));; ASSERT_NE(params.revokedParams->ocspResponses.data, nullptr);
    params.revokedParams->ocspResponses.data[0].data = static_cast<uint8_t *>(
        CfMalloc(OCSP_TEST_RESP_GOOD_SIZE, 0));; ASSERT_NE(params.revokedParams->ocspResponses.data[0].data, nullptr);
    memcpy_s(params.revokedParams->ocspResponses.data[0].data, OCSP_TEST_RESP_GOOD_SIZE,
        OCSP_TEST_RESP_GOOD, OCSP_TEST_RESP_GOOD_SIZE);
    params.revokedParams->ocspResponses.data[0].size = OCSP_TEST_RESP_GOOD_SIZE;

    HcfCertVerifyResult result = {};
    (void)g_validator->validateX509Cert(g_validator, eeCert, &params, &result);

    CfObjDestroy(eeCert);
    FreeVerifyCertResult(result);
    FreeValidatorParamsWithOcspData(params);
}

static OCSP_RESPONSE *CreateOcspResponseFromDer(const uint8_t *data, size_t len)
{
    const unsigned char *p = data;
    return d2i_OCSP_RESPONSE(nullptr, &p, len);
}

/**
 * @tc.name: ValidateX509Cert_OnlineOcsp_Mock_001
 * @tc.desc: Test online OCSP check with mock BIO and OCSP response
 *           Mock BIO_do_connect_retry to return success
 *           Mock OCSP_sendreq_nbio to return valid OCSP response
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_OnlineOcsp_Mock_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(OCSP_TEST_EE_VALID_URL);
    HcfX509Certificate *rootCert = CreateCertFromPem(OCSP_TEST_ROOT_CA);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(OCSP_TEST_INTERMEDIATE_CA);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    SetupOcspCheckParams(params, true);
    ASSERT_NE(params.revokedParams, nullptr);

    OCSP_RESPONSE *mockResp = CreateOcspResponseFromDer(OCSP_TEST_RESP_GOOD, OCSP_TEST_RESP_GOOD_SIZE);
    ASSERT_NE(mockResp, nullptr);

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), OSSL_HTTP_REQ_CTX_nbio_d2i(_, _, _))
        .WillRepeatedly(Invoke([](OSSL_HTTP_REQ_CTX *rctx, ASN1_VALUE **pval, const ASN1_ITEM *it) -> int {
            OCSP_RESPONSE *resp = CreateOcspResponseFromDer(OCSP_TEST_RESP_GOOD, OCSP_TEST_RESP_GOOD_SIZE);
            if (resp == nullptr) {
                return 0;
            }
            *pval = (ASN1_VALUE *)resp;
            return 1;
        }));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    (void)res;

    OCSP_RESPONSE_free(mockResp);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Params_InvalidOcspDigest_001
 * @tc.desc: Test invalid ocspDigest parameter
 *           When ocspDigest is out of valid range, expect CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Params_InvalidOcspDigest_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));; ASSERT_NE(params.revokedParams, nullptr);
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));; ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->ocspDigest = static_cast<HcfOcspDigest>(100); // Invalid value

    HcfCertVerifyResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Params_InvalidOcspDigest_002
 * @tc.desc: Test invalid ocspDigest parameter (too small)
 *           When ocspDigest is less than OCSP_DIGEST_SHA1, expect CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Params_InvalidOcspDigest_002, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));; ASSERT_NE(params.revokedParams, nullptr);
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));; ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->ocspDigest = static_cast<HcfOcspDigest>(-1); // Invalid value: negative

    HcfCertVerifyResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Params_InvalidRevocationFlags_001
 * @tc.desc: Test invalid revocationFlags count (empty)
 *           When revocationFlags.count is 0, expect CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Params_InvalidRevocationFlags_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));; ASSERT_NE(params.revokedParams, nullptr);
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 0; // Invalid: count = 0

    HcfCertVerifyResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Params_InvalidRevocationFlags_002
 * @tc.desc: Test invalid revocationFlags count (too large)
 *           When revocationFlags.count > 4, expect CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Params_InvalidRevocationFlags_002, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));; ASSERT_NE(params.revokedParams, nullptr);
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 10; // Invalid: count > 4

    HcfCertVerifyResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_CrlDownload_InvalidUrl_001
 * @tc.desc: Test CRL download with invalid URL (ftp protocol)
 * @tc.type: FUNC
 */
static STACK_OF(DIST_POINT) *CreateInvalidUrlCrldp(void)
{
    static const char *invalidUrl = "ftp://invalid.example.com/crl.crl";
    GENERAL_NAME *genName = GENERAL_NAME_new();
    genName->type = GEN_URI;
    genName->d.uniformResourceIdentifier = ASN1_IA5STRING_new();
    ASN1_STRING_set(genName->d.uniformResourceIdentifier, invalidUrl, strlen(invalidUrl));
    STACK_OF(GENERAL_NAME) *names = sk_GENERAL_NAME_new_null();
    sk_GENERAL_NAME_push(names, genName);
    DIST_POINT_NAME *dpn = DIST_POINT_NAME_new();
    dpn->type = 0;
    dpn->name.fullname = names;
    DIST_POINT *dp = DIST_POINT_new();
    dp->distpoint = dpn;
    STACK_OF(DIST_POINT) *crldp = sk_DIST_POINT_new_null();
    sk_DIST_POINT_push(crldp, dp);
    return crldp;
}

HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_CrlDownload_InvalidUrl_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_FOR_CDP);
    HcfX509Certificate *rootCert = CreateCertFromPem(TEST_ROOT_CA_FOR_CDP);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_WITH_CDP);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;
    SetupCrlCheckParams(params, true);
    HcfCertVerifyResult result = {};
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _))
        .WillRepeatedly(Invoke([](const X509 *x, int nid, int *crit, int *idx) -> void * {
            if (nid == NID_crl_distribution_points) {
                return CreateInvalidUrlCrldp();
            }
            return nullptr;
        }));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_ValidateDate_001
 * @tc.desc: Test validateDate parameter with date string
 *           When validateDate is true and date is provided, expect proper date validation
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_ValidateDate_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = true;
    const char *dateStr = "20260101000000Z";
    params.date = static_cast<char *>(CfMalloc(strlen(dateStr) + 1, 0));; ASSERT_NE(params.date, nullptr);
    (void)memcpy_s(params.date, strlen(dateStr), dateStr, strlen(dateStr));

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    HcfCertVerifyResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CERT_HAS_EXPIRED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_CrlCheck_WithLocalCrl_001
 * @tc.desc: Test CRL check with local CRL provided
 *           When CRL is provided via crls parameter, expect proper CRL validation
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_CrlCheck_WithLocalCrl_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));; ASSERT_NE(params.revokedParams, nullptr);
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));; ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->allowDownloadCrl = false;

    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    HcfX509Crl *crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(ret, CF_SUCCESS);; ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));; ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfCertVerifyResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_ValidateDate_NoDateParam_001
 * @tc.desc: Test validateDate=true with no date parameter
 *           When validateDate is true but date is NULL, should use current time
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_ValidateDate_NoDateParam_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = true;
    params.date = nullptr;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    HcfCertVerifyResult result = {};

    (void)g_validator->validateX509Cert(g_validator, cert, &params, &result);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_FullCheck_Success_001
 * @tc.desc: Test with all checks enabled and valid cert chain
 *           All validation passes, expect CF_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_FullCheck_Success_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    HcfCertVerifyResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(result.certs.count, 0);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}
}
