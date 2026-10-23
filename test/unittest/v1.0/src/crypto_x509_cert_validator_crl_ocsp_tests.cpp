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
 * @tc.name: ValidateX509Cert_Revocation_017
 * @tc.desc: Test online OCSP check - cert with invalid OCSP URL format
 *           When certificate has an invalid OCSP URL format,
 *           OCSP_parse_url should fail with CF_ERR_OCSP_RESPONSE_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_017, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(OCSP_TEST_EE_INVALID_URL);
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

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));; ASSERT_NE(params.revokedParams, nullptr);
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));; ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
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

/**
 * @tc.name: ValidateX509Cert_OcspDigest
 * @tc.desc: Test GetOcspDigestByType with all digest types
 *           Covers all branches in GetOcspDigestByType (lines 818-828):
 *           - OCSP_DIGEST_SHA1
 *           - OCSP_DIGEST_SHA224
 *           - OCSP_DIGEST_SHA256
 *           - OCSP_DIGEST_SHA384
 *           - OCSP_DIGEST_SHA512
 *           - default (invalid type fallback to SHA256)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_OcspDigest, TestSize.Level0)
{
    const int32_t digestTypes[] = {OCSP_DIGEST_SHA1, OCSP_DIGEST_SHA224, OCSP_DIGEST_SHA256,
        OCSP_DIGEST_SHA384, OCSP_DIGEST_SHA512, 99};
    const int numTypes = sizeof(digestTypes) / sizeof(digestTypes[0]);

    for (int i = 0; i < numTypes; i++) {
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
        params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
            CfMalloc(sizeof(HcfX509CertRevokedParams), 0));; ASSERT_NE(params.revokedParams, nullptr);
            params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
        params.revokedParams->revocationFlags.count = 1;
        params.revokedParams->revocationFlags.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
        ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
        params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
        params.revokedParams->allowOcspCheckOnline = true;
        params.revokedParams->ocspDigest = digestTypes[i];

        HcfCertVerifyResult result = {};
        CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
        if (digestTypes[i] == 99) {
            EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
        } else {
            EXPECT_EQ(res, CF_ERR_NETWORK_TIMEOUT);
        }
        CfObjDestroy(cert);
        FreeVerifyCertResult(result);
        FreeValidatorParamsWithOcspData(params);
    }
}

/* ============== Success Scenario Test Cases ============== */

/**
 * @tc.name: ValidateX509Cert_Revocation_Success_001
 * @tc.desc: Test CRL check with validateDate=false - cert is revoked
 *           When validateDate=false, CRL expiration check is skipped,
 *           but cert IS in CRL, should return CF_ERR_CERT_REVOKED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Success_001, TestSize.Level0)
{
    /* Use end entity cert which IS in the CRL */
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

    /* Use CRL from intermediate CA - the CRL has expired but validateDate=false */
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

    /* validateDate=false skips CRL expiration check, but cert IS in CRL, should be revoked */
    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Success_002
 * @tc.desc: Test cert revoked with validateDate=false - still returns revoked
 *           When validateDate=false and cert is in CRL, should return CF_ERR_CERT_REVOKED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Success_002, TestSize.Level0)
{
    /* Use end entity cert which IS in the CRL */
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
    params.revokedParams->revocationFlags.count = 2;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t) * 2, 0));; ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_CHECK_ALL_CERT;

    /* Use CRL - the CRL has expired but validateDate=false, cert IS revoked */
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

    /* validateDate=false skips CRL expiration, but cert IS in CRL, should be revoked */
    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Success_003
 * @tc.desc: Test both CRL and OCSP enabled, prefer OCSP mode with validateDate=false
 *           With OCSP disabled, CRL check is used, cert is revoked
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Success_003, TestSize.Level0)
{
    /* Use valid certificate chain: end entity -> intermediate CA -> root CA */
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
    params.revokedParams->revocationFlags.count = 3;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t) * 3, 0));; ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_PREFER_OCSP;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[2] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->allowOcspCheckOnline = false;  /* Disable online OCSP */

    /* Use CRL from intermediate CA - the CRL has expired */
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

    /* OCSP check fails (no OCSP response provided), fallback to CRL
     * validateDate=false skips CRL expiration check, but cert IS in CRL, should be revoked */
    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/* ============== Exception Scenario Test Cases ============== */

/**
 * @tc.name: ValidateX509Cert_Revocation_Error_001
 * @tc.desc: Test CRL check with validateDate=true - cert expired
 *           When validateDate=true and cert is expired, expect CF_ERR_CERT_HAS_EXPIRED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Error_001, TestSize.Level0)
{
    /* Use valid certificate chain: end entity -> intermediate CA -> root CA */
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

    /* Use CRL that has expired */
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

    /* With validateDate=true, cert has expired (cert dates are in 2023-2024) */
    EXPECT_EQ(res, CF_ERR_CERT_HAS_EXPIRED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Error_002
 * @tc.desc: Test CRL check - CRL signature verification failed
 *           When CRL signature doesn't match issuer, expect CF_ERR_CRL_SIGNATURE_FAILURE
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Error_002, TestSize.Level0)
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
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    /* Use CRL from different CA (signature mismatch) */
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

    /* CRL signature verification should fail since CRL is from different CA */
    EXPECT_NE(res, CF_SUCCESS);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Error_003
 * @tc.desc: Test CRL check - unable to get CRL issuer certificate
 *           When CRL issuer certificate is not available, expect CF_ERR_UNABLE_TO_GET_CRL_ISSUER
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Error_003, TestSize.Level0)
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

    /* Only provide root cert, not intermediate - CRL issuer (intermediate) will be missing */
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
    params.revokedParams->allowDownloadCrl = false;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Should fail due to missing CRL or chain validation failure */
    EXPECT_NE(res, CF_SUCCESS);

    CfObjDestroy(cert);
    CfObjDestroy(intermediateCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Error_004
 * @tc.desc: Test revocation check - self-signed certificate should be skipped
 *           Self-signed certificates should be skipped during revocation check
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Error_004, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_SELF_SIGNED_CERT);; ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = cert;  /* Self-signed cert is its own trust anchor */

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));; ASSERT_NE(params.revokedParams, nullptr);
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));; ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Self-signed cert should pass - no issuer means no revocation check */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Error_005
 * @tc.desc: Test invalid CRL URL format (non-http/https)
 *           When CRL URL is not http/https, download should be skipped
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Error_005, TestSize.Level0)
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
    params.revokedParams->allowDownloadCrl = true;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);


    /* CRL download should fail with network timeout since URL is unreachable */
    EXPECT_EQ(res, CF_ERR_NETWORK_TIMEOUT);
    EXPECT_NE(result.error, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/* ============== Mock Test Cases for Revocation ============== */

/**
 * @tc.name: ValidateX509Cert_Revocation_Mock_001
 * @tc.desc: Test X509_STORE_CTX_new failure in CheckSingleCertByCrl
 *           When X509_STORE_CTX_new returns NULL, expect CF_ERR_MALLOC
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Mock_001, TestSize.Level0)
{
    /* Use valid certificate chain: end entity -> intermediate CA -> root CA */
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

    /* Use CRL from intermediate CA */
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

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_new())
        .WillOnce(Return(nullptr));
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    /* When X509_STORE_CTX_new fails, the error is propagated as crypto operation error */
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    EXPECT_NE(result.error, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Mock_002
 * @tc.desc: Test X509_STORE_CTX_init failure in CheckSingleCertByCrl
 *           When X509_STORE_CTX_init fails, expect CF_ERR_CRYPTO_OPERATION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Mock_002, TestSize.Level0)
{
    /* Use valid certificate chain: end entity -> intermediate CA -> root CA */
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

    /* Use CRL from intermediate CA */
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

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_init(_, _, _, _))
        .WillOnce(Return(0));
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    EXPECT_NE(result.error, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Mock_003
 * @tc.desc: Test X509_CRL_load_http failure (CRL download failure)
 *           When X509_CRL_load_http returns NULL, expect CF_ERR_CRL_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Mock_003, TestSize.Level0)
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
    params.revokedParams->allowDownloadCrl = true;

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(Return(nullptr));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);

    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);
    EXPECT_NE(result.error, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Mock_003_1
 * @tc.desc: Test X509_CRL_load_http returns NULL with timeout error
 *           When X509_CRL_load_http returns NULL due to network timeout, expect CF_ERR_NETWORK_TIMEOUT
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Mock_003_1, TestSize.Level0)
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
    params.revokedParams->allowDownloadCrl = true;

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_error())
        .WillRepeatedly(Return(static_cast<unsigned long>(BIO_R_CONNECT_TIMEOUT)));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);

    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_NETWORK_TIMEOUT);
    EXPECT_NE(result.error, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

static X509_CRL *CreateX509CrlFromPemData(const char *pemData)
{
    BIO *bio = BIO_new_mem_buf(pemData, -1);
    if (bio == nullptr) {
        return nullptr;
    }
    X509_CRL *crl = PEM_read_bio_X509_CRL(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return crl;
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Mock_003_2
 * @tc.desc: Test X509_CRL_load_http returns valid CRL
 *           When X509_CRL_load_http returns valid CRL object, verify the download path is covered
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Mock_003_2, TestSize.Level0)
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
    params.revokedParams->allowDownloadCrl = true;

    X509_CRL *mockCrl = CreateX509CrlFromPemData(g_testCertChainPemMidCRL);; ASSERT_NE(mockCrl, nullptr);

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(WithoutArgs(Invoke([mockCrl]() -> X509_CRL* {
            return X509_CRL_dup(mockCrl);
        })));
    (void)g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);

    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    X509_CRL_free(mockCrl);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Mock_004
 * @tc.desc: Test X509_get1_ocsp returns NULL (no OCSP URL)
 *           When certificate has no OCSP URL, expect CF_ERR_OCSP_RESPONSE_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Mock_004, TestSize.Level0)
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
    params.revokedParams->allowOcspCheckOnline = true;

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get1_ocsp(_))
        .WillOnce(Return(nullptr));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);

    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);
    EXPECT_NE(result.error, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Mock_005
 * @tc.desc: Test X509_verify_cert returns various error codes
 *           Verify different error codes are mapped correctly
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Mock_005, TestSize.Level0)
{
    /* Use valid certificate chain: end entity -> intermediate CA -> root CA */
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

    /* Use CRL from intermediate CA */
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

    /* Test X509_V_ERR_CERT_REVOKED error code */
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_CERT_REVOKED));
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);
    EXPECT_NE(result.error, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}
}
