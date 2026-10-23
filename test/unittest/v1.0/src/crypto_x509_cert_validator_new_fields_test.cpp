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

/* TDD test: new fields of HcfX509CertValidatorParams: trustCertPath / ipAddresses / extendedKeyUsage / sslMode */

#include <cstring>
#include "crypto_x509_cert_validator_test_common.h"

using namespace testing::ext;
using namespace CFMock;
using ::testing::Mock;
using ::testing::Return;
using ::testing::_;

/* Provided by cf_mock.cpp: force X509_check_ip_asc to return 1 (IP matched) */
extern "C" int g_mockX509CheckIpAsc;
/* Provided by cf_mock.cpp: X509_get_ext_d2i returns nullptr for NID_ext_key_usage */
extern "C" int g_mockX509GetExtD2iNull;
/* Provided by cf_mock.cpp: trustCertPath (non-system CA directory) load returns 1 (success) */
extern "C" int g_mockTrustCertPathLoadSuccess;
/* Provided by cf_mock.cpp: trustCertPath (non-system CA directory) load returns 0 (failure) */
extern "C" int g_mockTrustCertPathLoadFail;
/* Provided by cf_mock.cpp: X509_VERIFY_PARAM_set_purpose returns 0 (failure) */
extern "C" int g_mockX509VerifyParamSetPurposeFail;

namespace {
/* Set up a full trust chain: root CA as the trust anchor, intermediate CA as an untrusted intermediate certificate */
static void SetupFullChainParams(HcfX509CertValidatorParams &params)
{
    params.trustSystemCa = false;
    params.validateDate = false;
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    params.trustedCerts.data[0] = CreateCertFromPem(TEST_ROOT_CA_CERT);
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    params.untrustedCerts.data[0] = CreateCertFromPem(TEST_INTERMEDIATE_CA_CERT);
}

static void SetupStringArray(HcfStringArray &arr, const char *str)
{
    arr.count = 1;
    arr.data = static_cast<char **>(CfMalloc(sizeof(char *), 0));
    if (arr.data != nullptr) {
        arr.data[0] = static_cast<char *>(CfMalloc(strlen(str) + 1, 0));
        if (arr.data[0] != nullptr) {
            (void)memcpy_s(arr.data[0], strlen(str) + 1, str, strlen(str) + 1);
        }
    }
}
} // namespace

/**
 * @tc.name: ValidateX509Cert_TrustCertPath_InvalidPath_001
 * @tc.desc: trustCertPath points to a nonexistent directory, load failure should return CF_ERR_CRYPTO_OPERATION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_TrustCertPath_InvalidPath_001, TestSize.Level0)
{
    g_mockTrustCertPathLoadFail = 1;  /* trustCertPath load returns 0 (failure) */

    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;
    SetupStringArray(params.trustCertPath, "/invalid/nonexistent/trust/cert/dir");

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    g_mockTrustCertPathLoadFail = 0;
}

/**
 * @tc.name: ValidateX509Cert_TrustCertPath_Success_001
 * @tc.desc: trustCertPath points to a valid directory (mock load success),
 * ConstructTrustedStore returns success and chain verification passes returning CF_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_TrustCertPath_Success_001, TestSize.Level0)
{
    g_mockTrustCertPathLoadSuccess = 1;  /* trustCertPath loaded successfully */

    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    SetupStringArray(params.trustCertPath, "/valid/trust/cert/dir");

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    g_mockTrustCertPathLoadSuccess = 0;
}

/**
 * @tc.name: ValidateX509Cert_SslMode_SetPurposeFail_001
 * @tc.desc: when sslMode is SERVER, X509_VERIFY_PARAM_set_purpose fails, should return CF_ERR_CRYPTO_OPERATION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_SslMode_SetPurposeFail_001, TestSize.Level0)
{
    g_mockX509VerifyParamSetPurposeFail = 1;  /* X509_VERIFY_PARAM_set_purpose returns 0 (failure) */

    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    params.sslMode = SSL_MODE_SERVER;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    g_mockX509VerifyParamSetPurposeFail = 0;
}

/**
 * @tc.name: ValidateX509Cert_IpAddresses_Mismatch_001
 * @tc.desc: the IP specified by ipAddresses does not match the certificate SAN,
 * should return CF_ERR_CERT_IP_ADDRESS_MISMATCH
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_IpAddresses_Mismatch_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    SetupStringArray(params.ipAddresses, "192.168.1.1");

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CERT_IP_ADDRESS_MISMATCH);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_IpAddresses_Match_001
 * @tc.desc: the IP specified by ipAddresses matches the certificate SAN (mock X509_check_ip_asc returns 1),
 * should return CF_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_IpAddresses_Match_001, TestSize.Level0)
{
    /* Force X509_check_ip_asc to return 1 (IP matched) to cover the return CF_SUCCESS branch of CheckIpAddresses */
    g_mockX509CheckIpAsc = 1;

    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    SetupStringArray(params.ipAddresses, "192.168.1.1");

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    g_mockX509CheckIpAsc = 0;
}

/**
 * @tc.name: ValidateX509Cert_ExtendedKeyUsage_Match_001
 * @tc.desc: certificate contains serverAuth EKU, extendedKeyUsage set to SERVER_AUTH should verify successfully
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_ExtendedKeyUsage_Match_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    params.extendedKeyUsage.count = 1;
    params.extendedKeyUsage.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.extendedKeyUsage.data, nullptr);
    params.extendedKeyUsage.data[0] = EKU_TLS_SERVER_AUTH;

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
 * @tc.name: ValidateX509Cert_ExtendedKeyUsage_Mismatch_001
 * @tc.desc: certificate only contains serverAuth EKU,
 * specifying CLIENT_AUTH should return CF_ERR_CERT_EXTENDED_KEY_USAGE_MISMATCH
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_ExtendedKeyUsage_Mismatch_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    params.extendedKeyUsage.count = 1;
    params.extendedKeyUsage.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.extendedKeyUsage.data, nullptr);
    params.extendedKeyUsage.data[0] = EKU_TLS_CLIENT_AUTH;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CERT_EXTENDED_KEY_USAGE_MISMATCH);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_ExtendedKeyUsage_NoExt_001
 * @tc.desc: certificate has no EKU extension (mock X509_get_ext_d2i returns NULL),
 * specifying extendedKeyUsage should return CF_ERR_CERT_EXTENDED_KEY_USAGE_MISMATCH
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_ExtendedKeyUsage_NoExt_001, TestSize.Level0)
{
    /* X509_get_ext_d2i returns NULL for NID_ext_key_usage to cover the extUsage==NULL branch */
    g_mockX509GetExtD2iNull = 1;

    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    params.extendedKeyUsage.count = 1;
    params.extendedKeyUsage.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.extendedKeyUsage.data, nullptr);
    params.extendedKeyUsage.data[0] = EKU_TLS_SERVER_AUTH;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CERT_EXTENDED_KEY_USAGE_MISMATCH);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    g_mockX509GetExtD2iNull = 0;
}

/**
 * @tc.name: ValidateX509Cert_ExtendedKeyUsage_InvalidType_001
 * @tc.desc: extendedKeyUsage specifies an invalid EKU type (out of range), should return CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_ExtendedKeyUsage_InvalidType_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    params.extendedKeyUsage.count = 1;
    params.extendedKeyUsage.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.extendedKeyUsage.data, nullptr);
    params.extendedKeyUsage.data[0] = MAX_EXTENDED_KEY_USAGE_COUNT;  /* Out-of-range invalid EKU type */

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_SslMode_Server_001
 * @tc.desc: certificate contains serverAuth, sslMode SERVER should verify successfully
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_SslMode_Server_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    params.sslMode = SSL_MODE_SERVER;

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
 * @tc.name: ValidateX509Cert_SslMode_Client_Mismatch_001
 * @tc.desc: certificate only contains serverAuth, sslMode CLIENT (requires clientAuth) should fail verification
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_SslMode_Client_Mismatch_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    params.sslMode = SSL_MODE_CLIENT;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_NE(res, CF_SUCCESS);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_NoTrustSource_001
 * @tc.desc: no trust source set (trustedCerts/trustCertPath empty and trustSystemCa=false),
 * should return CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_NoTrustSource_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_NoTrustSource_NullData_001
 * @tc.desc: trustedCerts/trustCertPath data is NULL and count is 0,
 * trustSystemCa=false, should return CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_NoTrustSource_NullData_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.trustedCerts.count = 0;
    params.trustedCerts.data = nullptr;
    params.trustCertPath.count = 0;
    params.trustCertPath.data = nullptr;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_NoTrustSource_TrustCertPathEmpty_001
 * @tc.desc: trustCertPath.data is non-NULL but count is 0, trustedCerts empty and trustSystemCa=false,
 * should return CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_NoTrustSource_TrustCertPathEmpty_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.trustCertPath.count = 0;
    params.trustCertPath.data = static_cast<char **>(CfMalloc(sizeof(char *), 0));

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}


/**
 * @tc.name: ValidateX509Cert_TrustCertPath_CountExceed_001
 * @tc.desc: trustCertPath count exceeds MAX_TRUST_CERT_PATH_COUNT, should return CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_TrustCertPath_CountExceed_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    params.trustCertPath.count = MAX_TRUST_CERT_PATH_COUNT + 1;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_TrustCertPath_Null_001
 * @tc.desc: trustCertPath array element is NULL, should return CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_TrustCertPath_Null_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    params.trustCertPath.count = 1;
    params.trustCertPath.data = static_cast<char **>(CfMalloc(sizeof(char *), 0));
    ASSERT_NE(params.trustCertPath.data, nullptr);
    params.trustCertPath.data[0] = nullptr;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_TrustCertPath_TooLong_001
 * @tc.desc: trustCertPath path length exceeds MAX_TRUST_CERT_PATH_LENGTH, should return CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_TrustCertPath_TooLong_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    std::string longPath(MAX_TRUST_CERT_PATH_LENGTH + 1, 'a');
    SetupStringArray(params.trustCertPath, longPath.c_str());

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_IpAddresses_CountExceed_001
 * @tc.desc: ipAddresses count exceeds MAX_IP_ADDRESSES_COUNT, should return CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_IpAddresses_CountExceed_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    params.ipAddresses.count = MAX_IP_ADDRESSES_COUNT + 1;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_IpAddresses_Null_001
 * @tc.desc: ipAddresses array element is NULL, should return CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_IpAddresses_Null_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    params.ipAddresses.count = 1;
    params.ipAddresses.data = static_cast<char **>(CfMalloc(sizeof(char *), 0));
    ASSERT_NE(params.ipAddresses.data, nullptr);
    params.ipAddresses.data[0] = nullptr;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_IpAddresses_TooLong_001
 * @tc.desc: ipAddresses string length exceeds MAX_IP_ADDRESS_LENGTH, should return CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_IpAddresses_TooLong_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    std::string longIp(MAX_IP_ADDRESS_LENGTH + 1, 'a');
    SetupStringArray(params.ipAddresses, longIp.c_str());

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_ExtendedKeyUsage_CountExceed_001
 * @tc.desc: extendedKeyUsage count exceeds MAX_EXTENDED_KEY_USAGE_COUNT, should return CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_ExtendedKeyUsage_CountExceed_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    params.extendedKeyUsage.count = MAX_EXTENDED_KEY_USAGE_COUNT + 1;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_SslMode_OutOfRange_001
 * @tc.desc: sslMode out of HcfSslMode range (> SSL_MODE_SERVER), should return CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_SslMode_OutOfRange_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    params.sslMode = SSL_MODE_SERVER + 1;

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_TrustSource_TrustCertPathWithSystemCa_001
 * @tc.desc: trustCertPath has a value and trustSystemCa=true, trustedCerts empty
 *           (one of the three-condition combinations of CheckTrustSourceParams), no parameter error,
 *           subsequent trustCertPath load failure returns CF_ERR_CRYPTO_OPERATION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_TrustSource_TrustCertPathWithSystemCa_001, TestSize.Level0)
{
    g_mockTrustCertPathLoadFail = 1;  /* trustCertPath load returns 0 (failure) */

    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = true;
    params.validateDate = false;
    SetupStringArray(params.trustCertPath, "/invalid/nonexistent/trust/cert/dir");

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    g_mockTrustCertPathLoadFail = 0;
}

/**
 * @tc.name: ValidateX509Cert_SslMode_BelowRange_001
 * @tc.desc: sslMode less than SSL_MODE_NONE (negative), covers the
 *           sslMode < SSL_MODE_NONE sub-condition in CheckEnhancedCertParams, should return CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_SslMode_BelowRange_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    params.sslMode = SSL_MODE_NONE - 1;  /* -1, less than SSL_MODE_NONE */

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ConstructTrustedStore_TrustCertPathLoadFail_001
 * @tc.desc: trustCertPath load fails (mock X509_STORE_load_locations returns 0),
 *           covers the loadRet != 1 branch in ConstructTrustedStore
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ConstructTrustedStore_TrustCertPathLoadFail_001, TestSize.Level0)
{
    g_mockTrustCertPathLoadFail = 1;  /* trustCertPath load returns 0 (failure) */

    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    params.trustSystemCa = false;
    params.validateDate = false;
    SetupStringArray(params.trustCertPath, "/valid/trust/cert/dir");

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    g_mockTrustCertPathLoadFail = 0;
}

/**
 * @tc.name: ValidateX509Cert_TrustSource_FullChainTrustPathSystemCa_001
 * @tc.desc: trustedCerts has a value and trustCertPath has a value and trustSystemCa=true
 *           (one of the three-condition combinations of CheckTrustSourceParams), no parameter error,
 *           subsequent trustCertPath load failure returns CF_ERR_CRYPTO_OPERATION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_TrustSource_FullChainTrustPathSystemCa_001, TestSize.Level0)
{
    g_mockTrustCertPathLoadFail = 1;  /* trustCertPath load returns 0 (failure) */

    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    params.trustSystemCa = true;
    SetupStringArray(params.trustCertPath, "/invalid/nonexistent/trust/cert/dir");

    HcfCertVerifyResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    g_mockTrustCertPathLoadFail = 0;
}

/**
 * @tc.name: SetSslPurposeIfNeeded_Get0ParamNull_001
 * @tc.desc: sslMode is SERVER and X509_STORE_CTX_get0_param returns NULL,
 *           covers the verifyParam == NULL branch in SetSslPurposeIfNeeded
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, SetSslPurposeIfNeeded_Get0ParamNull_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(TEST_END_ENTITY_CERT);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.size = sizeof(HcfX509CertValidatorParams);
    SetupFullChainParams(params);
    params.sslMode = SSL_MODE_SERVER;

    HcfCertVerifyResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get0_param(_))
        .WillRepeatedly(Return(nullptr));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}
