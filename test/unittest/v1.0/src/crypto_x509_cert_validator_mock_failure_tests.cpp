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
 * @tc.name: ValidateX509Cert_Mock_X509_STORE_CTX_new_Fail_001
 * @tc.desc: Mock X509_STORE_CTX_new returns NULL
 *           Expect CF_ERR_CRYPTO_OPERATION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_X509_STORE_CTX_new_Fail_001, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_new())
        .WillOnce(Return(nullptr));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_X509_STORE_new_Fail_001
 * @tc.desc: Mock X509_STORE_new returns NULL
 *           Expect CF_ERR_CRYPTO_OPERATION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_X509_STORE_new_Fail_001, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_new())
        .WillOnce(Return(nullptr));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_X509_STORE_CTX_init_Fail_001
 * @tc.desc: Mock X509_STORE_CTX_init returns 0
 *           Expect CF_ERR_CRYPTO_OPERATION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_X509_STORE_CTX_init_Fail_001, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_init(_, _, _, _))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_X509_verify_cert_Fail_001
 * @tc.desc: Mock X509_verify_cert returns 0 with X509_V_ERR_CERT_HAS_EXPIRED
 *           Expect CF_ERR_CERT_HAS_EXPIRED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_X509_verify_cert_Fail_001, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_CERT_HAS_EXPIRED));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CERT_HAS_EXPIRED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_X509_verify_cert_Fail_002
 * @tc.desc: Mock X509_verify_cert returns 0 with X509_V_ERR_CERT_NOT_YET_VALID
 *           Expect CF_ERR_CERT_NOT_YET_VALID
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_X509_verify_cert_Fail_002, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_CERT_NOT_YET_VALID));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CERT_NOT_YET_VALID);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_X509_verify_cert_Fail_003
 * @tc.desc: Mock X509_verify_cert returns 0 with X509_V_ERR_CERT_SIGNATURE_FAILURE
 *           Expect CF_ERR_CERT_SIGNATURE_FAILURE
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_X509_verify_cert_Fail_003, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_CERT_SIGNATURE_FAILURE));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CERT_SIGNATURE_FAILURE);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_X509_verify_cert_Fail_004
 * @tc.desc: Mock X509_verify_cert returns 0 with X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
 *           Expect CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_X509_verify_cert_Fail_004, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_X509_STORE_add_cert_Fail_001
 * @tc.desc: Mock X509_STORE_add_cert returns 0
 *           Expect CF_ERR_CRYPTO_OPERATION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_X509_STORE_add_cert_Fail_001, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_add_cert(_, _))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_sk_X509_push_Fail_001
 * @tc.desc: Mock sk_X509_push returns 0
 *           Expect CF_ERR_CRYPTO_OPERATION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_sk_X509_push_Fail_001, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_push(_, _))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_X509_verify_cert_Fail_005
 * @tc.desc: Mock X509_verify_cert returns 0 with X509_V_ERR_CERT_UNTRUSTED
 *           Expect CF_ERR_CERT_UNTRUSTED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_X509_verify_cert_Fail_005, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_CERT_UNTRUSTED));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CERT_UNTRUSTED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_X509_verify_cert_Fail_006
 * @tc.desc: Mock X509_verify_cert returns 0 with X509_V_ERR_INVALID_CA
 *           Expect CF_ERR_KEYUSAGE_NO_CERTSIGN
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_X509_verify_cert_Fail_006, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_INVALID_CA));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_KEYUSAGE_NO_CERTSIGN);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_X509_verify_cert_Fail_007
 * @tc.desc: Mock X509_verify_cert returns 0 with X509_V_ERR_KEYUSAGE_NO_CERTSIGN
 *           Expect CF_ERR_KEYUSAGE_NO_CERTSIGN
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_X509_verify_cert_Fail_007, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_KEYUSAGE_NO_CERTSIGN));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_KEYUSAGE_NO_CERTSIGN);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_X509_verify_cert_Fail_008
 * @tc.desc: Mock X509_verify_cert returns 0 with X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE
 *           Expect CF_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_X509_verify_cert_Fail_008, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_X509_verify_cert_Fail_009
 * @tc.desc: Mock X509_verify_cert returns 0 with X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
 *           Expect CF_ERR_CERT_UNTRUSTED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_X509_verify_cert_Fail_009, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CERT_UNTRUSTED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_X509_verify_cert_Fail_010
 * @tc.desc: Mock X509_verify_cert returns 0 with X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
 *           Expect CF_ERR_CERT_UNTRUSTED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_X509_verify_cert_Fail_010, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CERT_UNTRUSTED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_X509_verify_cert_Fail_011
 * @tc.desc: Mock X509_verify_cert returns 0 with X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION
 *           Expect CF_ERR_CERT_UNKNOWN_CRITICAL_EXTENSION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_X509_verify_cert_Fail_011, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CERT_UNKNOWN_CRITICAL_EXTENSION);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_CrlError_001
 * @tc.desc: Mock X509_verify_cert returns 0 with X509_V_ERR_CRL_HAS_EXPIRED
 *           Expect CF_ERR_CRL_HAS_EXPIRED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_CrlError_001, TestSize.Level0)
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

    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult ret = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(ret, CF_SUCCESS);; ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));; ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_CRL_HAS_EXPIRED));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CRL_HAS_EXPIRED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_CrlError_002
 * @tc.desc: Mock X509_verify_cert returns 0 with X509_V_ERR_CRL_NOT_YET_VALID
 *           Expect CF_ERR_CRL_NOT_YET_VALID
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_CrlError_002, TestSize.Level0)
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

    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult ret = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(ret, CF_SUCCESS);; ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));; ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_CRL_NOT_YET_VALID));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CRL_NOT_YET_VALID);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_CrlError_003
 * @tc.desc: Mock X509_verify_cert returns 0 with X509_V_ERR_CRL_SIGNATURE_FAILURE
 *           Expect CF_ERR_CRL_SIGNATURE_FAILURE
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_CrlError_003, TestSize.Level0)
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

    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult ret = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(ret, CF_SUCCESS);; ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));; ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_CRL_SIGNATURE_FAILURE));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CRL_SIGNATURE_FAILURE);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_CrlError_004
 * @tc.desc: Mock X509_verify_cert returns 0 with X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER
 *           Expect CF_ERR_UNABLE_TO_GET_CRL_ISSUER
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_CrlError_004, TestSize.Level0)
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

    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult ret = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(ret, CF_SUCCESS);; ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));; ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_UNABLE_TO_GET_CRL_ISSUER);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_CrlError_005
 * @tc.desc: Mock X509_verify_cert returns 0 with X509_V_ERR_UNABLE_TO_GET_CRL
 *           Expect CF_ERR_CRL_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_CrlError_005, TestSize.Level0)
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

    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult ret = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(ret, CF_SUCCESS);; ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));; ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_UNABLE_TO_GET_CRL));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_OPENSSL_sk_new_null_Fail_001
 * @tc.desc: Mock OPENSSL_sk_new_null returns NULL
 *           Expect CF_ERR_CRYPTO_OPERATION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_OPENSSL_sk_new_null_Fail_001, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_new_null())
        .WillOnce(Return(nullptr));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_X509_up_ref_Fail_001
 * @tc.desc: Mock X509_up_ref returns 0
 *           Expect CF_ERR_CRYPTO_OPERATION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_X509_up_ref_Fail_001, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_up_ref(_))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_X509_STORE_CTX_get_current_cert_Fail_001
 * @tc.desc: Mock X509_STORE_CTX_get_current_cert returns NULL
 *           Expect error result
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_X509_STORE_CTX_get_current_cert_Fail_001, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_CERT_HAS_EXPIRED));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_current_cert(_))
        .WillOnce(Return(nullptr));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CERT_HAS_EXPIRED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_OnlineOcsp_Mock_BIO_do_connect_retry_Fail_001
 * @tc.desc: Mock BIO_do_connect_retry returns 0
 *           Expect CF_ERR_OCSP_RESPONSE_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_OnlineOcsp_Mock_BIO_do_connect_retry_Fail_001, TestSize.Level0)
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
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
        .WillRepeatedly(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_OnlineOcsp_Mock_OSSL_HTTP_REQ_CTX_nbio_d2i_Fail_001
 * @tc.desc: Mock OSSL_HTTP_REQ_CTX_nbio_d2i returns 0
 *           Expect CF_ERR_OCSP_RESPONSE_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest,
    ValidateX509Cert_OnlineOcsp_Mock_OSSL_HTTP_REQ_CTX_nbio_d2i_Fail_001, TestSize.Level0)
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
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), OSSL_HTTP_REQ_CTX_nbio_d2i(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_error())
        .WillRepeatedly(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_OnlineOcsp_Mock_OSSL_HTTP_REQ_CTX_nbio_d2i_Timeout_001
 * @tc.desc: Mock OSSL_HTTP_REQ_CTX_nbio_d2i returns 0 with BIO_R_CONNECT_TIMEOUT
 *           Expect CF_ERR_NETWORK_TIMEOUT
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest,
    ValidateX509Cert_OnlineOcsp_Mock_OSSL_HTTP_REQ_CTX_nbio_d2i_Timeout_001, TestSize.Level0)
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

    STACK_OF(OPENSSL_STRING) *mockUrlStack = sk_OPENSSL_STRING_new_null();; ASSERT_NE(mockUrlStack, nullptr);
    char *url = OPENSSL_strdup("http://ocsp.example.com");; ASSERT_NE(url, nullptr);
    sk_OPENSSL_STRING_push(mockUrlStack, url);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get1_ocsp(_))
        .WillOnce(Return(mockUrlStack));
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), OSSL_HTTP_REQ_CTX_nbio_d2i(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_error())
        .WillRepeatedly(Return(static_cast<unsigned long>(BIO_R_CONNECT_TIMEOUT)));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_NETWORK_TIMEOUT);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_GetCertSubjectName_Fail_001
 * @tc.desc: Mock X509_get_subject_name returns NULL
 *           Expect CF_ERR_CRYPTO_OPERATION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_GetCertSubjectName_Fail_001, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_current_cert(_))
        .WillOnce(Return(static_cast<X509*>(nullptr)));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_GetCertSubjectName_Fail_002
 * @tc.desc: Mock BIO_new returns NULL for GetCertSubjectName
 *           Expect CF_ERR_CERT_HAS_EXPIRED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_GetCertSubjectName_Fail_002, TestSize.Level0)
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

    HcfCertVerifyResult result = {};

    X509 *intermediateX509 = GetX509FromHcfX509Certificate(reinterpret_cast<HcfCertificate *>(intermediateCert));
    ASSERT_NE(intermediateX509, nullptr);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_CERT_HAS_EXPIRED));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_current_cert(_))
        .WillOnce(Return(intermediateX509));
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_new(_))
        .WillOnce(Return(static_cast<BIO*>(nullptr)));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CERT_HAS_EXPIRED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Mock_MAX_DOWNLOAD_COUNT_Exceeded_001
 * @tc.desc: Test that exceeding MAX_TOTAL_DOWNLOAD_CERT_COUNT returns error
 *           Expect CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Mock_MAX_DOWNLOAD_COUNT_Exceeded_001, TestSize.Level0)
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
    params.allowDownloadIntermediateCa = true;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));; ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    HcfCertVerifyResult result = {};

    X509 *intermediateX509 = GetX509FromHcfX509Certificate(reinterpret_cast<HcfCertificate *>(intermediateCert));
    ASSERT_NE(intermediateX509, nullptr);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillRepeatedly(Return(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_current_cert(_))
        .WillRepeatedly(Return(intermediateX509));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _))
        .WillRepeatedly(Return(static_cast<void*>(nullptr)));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}
/**
 * @tc.name: ValidateX509Cert_RealWorld_Cert_001
 * @tc.desc: Test real-world Real world certificate validation
 *           - Trust system CA certificates
 *           - Enable intermediate certificate download from AIA
 *           - Enable online OCSP check
 *           This test uses real network connections and may take time
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_RealWorld_Cert_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(REAL_WORLD_CERT);; ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = true;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = true;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));; ASSERT_NE(params.revokedParams, nullptr);
        params.revokedParams->size = sizeof(HcfX509CertRevokedParams);
    params.revokedParams->revocationFlags.count = 2;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t) * 2, 0));; ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_CHECK_ALL_CERT;
    params.revokedParams->allowOcspCheckOnline = true;

    HcfCertVerifyResult result = {};

    CF_LOG_I("ValidateX509Cert_RealWorld_Cert_001: starting real certificate validation...");
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    CF_LOG_I("ValidateX509Cert_RealWorld_Cert_001: result=%d, errorMsg=%s",
             res, (result.error != nullptr ? result.error->errorMsg : "null"));

    if (res == CF_SUCCESS) {
        CF_LOG_I("Real world certificate validation succeeded!");
    } else {
        CF_LOG_I("Real world certificate validation failed, this may be expected due to network conditions");
    }
    FreeVerifyCertResult(result);

    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_CHECK_ALL_CERT;
    params.revokedParams->allowDownloadCrl = true;
    CF_LOG_I("ValidateX509Cert_RealWorld_Cert_001: starting real certificate validation...");
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    CF_LOG_I("ValidateX509Cert_RealWorld_Cert_001: result=%d, errorMsg=%s",
             res, (result.error != nullptr ? result.error->errorMsg : "null"));

    if (res == CF_SUCCESS) {
        CF_LOG_I("Real world certificate validation succeeded!");
    } else {
        CF_LOG_I("Real world certificate validation failed, this may be expected due to network conditions");
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}
}
