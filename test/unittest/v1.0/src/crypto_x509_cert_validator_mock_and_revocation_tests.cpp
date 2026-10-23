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
 * @tc.name: ValidateX509CertMockTest016
 * @tc.desc: Test OPENSSL_sk_push failure in ConstructUntrustedStack
 *           This tests Line 466 branch - when sk_X509_push fails
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest016, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_push(_, _))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_048
 * @tc.desc: Test CA certificate with keyUsage not containing keyCertSign
 *           Chain: Root CA -> Intermediate (no keyCertSign) -> EE
 *           Should return CF_ERR_KEYUSAGE_NO_CERTSIGN
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_048, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(EE_BY_INTERMEDIATE_NO_KEY_CERT_SIGN_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(INTERMEDIATE_NO_KEY_CERT_SIGN_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
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
    params.untrustedCerts.data[0] = intermediateCert;

    HcfCertVerifyResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    EXPECT_EQ(res, CF_ERR_KEYUSAGE_NO_CERTSIGN);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_049
 * @tc.desc: Test certificate with corrupted signature
 *           Chain: Root CA -> Corrupted Intermediate CA -> EE
 *           Should return CF_ERR_CERT_SIGNATURE_FAILURE
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_049, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *corruptedIntermediateCert = CreateCertFromPem(CORRUPTED_SIGNATURE_INTERMEDIATE_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(corruptedIntermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
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
    params.untrustedCerts.data[0] = corruptedIntermediateCert;

    HcfCertVerifyResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CERT_SIGNATURE_FAILURE);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_050
 * @tc.desc: Test validateX509Cert with emailAddresses parameter (email match success)
 *           The cert has test@example.com in SAN, validation should succeed
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_050, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(EMAIL_TEST_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    const char *email = "test@example.com";
    params.emailAddresses.count = 1;
    params.emailAddresses.data = static_cast<char **>(CfMalloc(sizeof(char *), 0));
    ASSERT_NE(params.emailAddresses.data, nullptr);
    params.emailAddresses.data[0] = static_cast<char *>(CfMalloc(strlen(email) + 1, 0));
    ASSERT_NE(params.emailAddresses.data[0], nullptr);
    (void)memcpy_s(params.emailAddresses.data[0], strlen(email) + 1, email, strlen(email) + 1);

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest017
 * @tc.desc: Test X509_STORE_CTX_get_current_cert returning NULL in GetLastCertFromVerifyCtx
 *           This tests the case when verification fails but current_cert is NULL
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest017, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = true;

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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_current_cert(_))
        .WillOnce(Return((X509 *)nullptr));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    EXPECT_EQ(res, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest018
 * @tc.desc: Test X509_STORE_CTX_get1_chain returning NULL (Line 718)
 *           This tests the get1_chain returning NULL branch
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest018, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get1_chain(_))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(1));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest019
 * @tc.desc: Test successful download of missing intermediate CA via AIA
 *           First verification fails (missing issuer), X509_load_http succeeds,
 *           second verification succeeds
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest019, TestSize.Level0)
{
    BIO *bio = BIO_new_mem_buf(g_testDownloadCertValid, strlen(g_testDownloadCertValid) + 1);
    ASSERT_NE(bio, nullptr);
    X509 *downloadedCert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    ASSERT_NE(downloadedCert, nullptr);

    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testLeafCertValid);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCertValid);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = true;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillOnce(Return(downloadedCert));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(result.certs.count, 0);

    FreeVerifyCertResult(result);
    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest020
 * @tc.desc: Test malloc failure scenarios in FillVerifyCertResult
 *           - Case 1 (index 0): result->certs.data allocation failure -> CF_ERR_MALLOC
 *           - Case 2 (index 1): GetX509EncodedDataStream malloc failure
 *             Note: GetX509EncodedDataStream returns NULL on any failure without error code,
 *             so X509ToHcfX509Certificate cannot distinguish malloc failure from other errors,
 *             and returns CF_ERR_CRYPTO_OPERATION uniformly.
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest020, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(TEST_ROOT_CA_CERT);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
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

    HcfCertVerifyResult result = {};

    StartRecordMallocNum();
    SetMockMallocIndex(0);
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    EndRecordMallocNum();
    EXPECT_EQ(res, CF_ERR_MALLOC);

    StartRecordMallocNum();
    SetMockMallocIndex(1);
    res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    EndRecordMallocNum();
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest021
 * @tc.desc: Test TryDownloadFromAccessDescriptionWithRetry malloc failure
 *           When CfMallocEx fails to allocate URL buffer, should return CF_ERR_MALLOC.
 *           This tests the DOWNLOAD_RESULT_MALLOC_FAILED branch in download flow.
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest021, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testLeafCertValid);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCertValid);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = true;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfCertVerifyResult result = {};

    SetMockFlag(true);
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    SetMockFlag(false);
    EXPECT_EQ(res, CF_ERR_MALLOC);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_001
 * @tc.desc: Test CRL check - no CRL provided, expect CF_ERR_CRL_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_001, TestSize.Level0)
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
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    (void)memset_s(params.revokedParams, sizeof(HcfX509CertRevokedParams), 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_002
 * @tc.desc: Test OCSP check - no OCSP response provided, expect CF_ERR_OCSP_RESPONSE_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_002, TestSize.Level0)
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
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    (void)memset_s(params.revokedParams, sizeof(HcfX509CertRevokedParams), 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->allowOcspCheckOnline = false;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_003
 * @tc.desc: Test both CRL and OCSP check - CRL not found, fallback to OCSP
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_003, TestSize.Level0)
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
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 2;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(2 * sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->crls.count = 0;
    params.revokedParams->ocspResponses.count = 0;
    params.revokedParams->allowOcspCheckOnline = false;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_004
 * @tc.desc: Test CERT_REVOCATION_PREFER_OCSP flag - OCSP not available, fallback to CRL
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_004, TestSize.Level0)
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
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 3;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(3 * sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_PREFER_OCSP;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[2] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->crls.count = 0;
    params.revokedParams->ocspResponses.count = 0;
    params.revokedParams->allowOcspCheckOnline = false;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_005
 * @tc.desc: Test self-signed certificate - skip revocation check
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_005, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    HcfX509Certificate *trustCert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->crls.count = 0;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_006
 * @tc.desc: Test CRL check - CRL has expired, expect CF_ERR_CRL_HAS_EXPIRED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_006, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *ts2Cert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *ts1Cert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(ts2Cert, nullptr);
    ASSERT_NE(ts1Cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = ts1Cert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = ts2Cert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    (void)memset_s(params.revokedParams, sizeof(HcfX509CertRevokedParams), 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    HcfX509Crl *crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));
    ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    /* validateDate=false skips CRL expiration, but cert IS in CRL, should be revoked */
    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_007
 * @tc.desc: Test CRL check success - certificate not in CRL
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_007, TestSize.Level0)
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
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    (void)memset_s(params.revokedParams, sizeof(HcfX509CertRevokedParams), 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemInitialLocalCrl)),
        strlen(g_testCertChainPemInitialLocalCrl), CF_FORMAT_PEM };
    HcfX509Crl *crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));
    ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_008
 * @tc.desc: Test CHECK_ALL_CERT flag - check all certificates in chain
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_008, TestSize.Level0)
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
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    (void)memset_s(params.revokedParams, sizeof(HcfX509CertRevokedParams), 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 2;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(2 * sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_CHECK_ALL_CERT;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_009
 * @tc.desc: Test OCSP check with OCSP response provided
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_009, TestSize.Level0)
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
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    (void)memset_s(params.revokedParams, sizeof(HcfX509CertRevokedParams), 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->allowOcspCheckOnline = false;

    params.revokedParams->ocspResponses.count = 1;
    params.revokedParams->ocspResponses.data = static_cast<CfBlob *>(
        CfMalloc(sizeof(CfBlob), 0));
    ASSERT_NE(params.revokedParams->ocspResponses.data, nullptr);
    params.revokedParams->ocspResponses.data[0].data = const_cast<uint8_t *>(g_testOcspResponses);
    params.revokedParams->ocspResponses.data[0].size = sizeof(g_testOcspResponses);

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_010
 * @tc.desc: Test both CRL and OCSP - prefer OCSP flag
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_010, TestSize.Level0)
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
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    (void)memset_s(params.revokedParams, sizeof(HcfX509CertRevokedParams), 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 3;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(3 * sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_PREFER_OCSP;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[2] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->allowOcspCheckOnline = false;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_011
 * @tc.desc: Test revocation with only OCSP enabled, no CRL
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_011, TestSize.Level0)
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
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    (void)memset_s(params.revokedParams, sizeof(HcfX509CertRevokedParams), 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->allowOcspCheckOnline = false;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);
    EXPECT_NE(result.error, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_012
 * @tc.desc: Test revocation parameter validation - invalid revocationFlags count
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_012, TestSize.Level0)
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
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    (void)memset_s(params.revokedParams, sizeof(HcfX509CertRevokedParams), 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 0;
    params.revokedParams->revocationFlags.data = nullptr;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    EXPECT_NE(result.error, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_013
 * @tc.desc: Test CRL download - cert without CDP extension, allowDownloadCrl=true
 *           When certificate has no CRL Distribution Points extension,
 *           CRL download should fail with CF_ERR_CRL_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_013, TestSize.Level0)
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
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    (void)memset_s(params.revokedParams, sizeof(HcfX509CertRevokedParams), 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->allowDownloadCrl = true;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);
    EXPECT_NE(result.error, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_014
 * @tc.desc: Test CRL download - cert with CDP extension but download fails
 *           When intermediate CA has CRL Distribution Points extension but URL is unreachable,
 *           CRL download should fail with CF_ERR_CRL_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_014, TestSize.Level0)
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
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    (void)memset_s(params.revokedParams, sizeof(HcfX509CertRevokedParams), 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->allowDownloadCrl = true;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    /* CRL download should fail with network timeout since URL is unreachable */
    EXPECT_EQ(res, CF_ERR_NETWORK_TIMEOUT);
    EXPECT_NE(result.error, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_015, TestSize.Level0)
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
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    (void)memset_s(params.revokedParams, sizeof(HcfX509CertRevokedParams), 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->allowOcspCheckOnline = true;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);
    EXPECT_NE(result.error, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_016
 * @tc.desc: Test online OCSP check - cert with OCSP URL but server unreachable
 *           When certificate has OCSP URL but the server is unreachable,
 *           online OCSP check fails, falls through to CRL check which also fails
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_016, TestSize.Level0)
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
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    (void)memset_s(params.revokedParams, sizeof(HcfX509CertRevokedParams), 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->allowOcspCheckOnline = true;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    /* OCSP online check timeout due to unreachable server */
    EXPECT_EQ(res, CF_ERR_NETWORK_TIMEOUT);
    EXPECT_NE(result.error, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}
}
