/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "crypto_x509_test_common.h"

#include <gtest/gtest.h>
#include <openssl/x509v3.h>

#include "cert_crl_common.h"
#include "certificate_openssl_common.h"
#include "cf_blob.h"
#include "cf_log.h"
#include "fwk_class.h"
#include "memory_mock.h"
#include "securec.h"
#include "x509_certificate.h"
#include "x509_certificate_openssl.h"
#include "certificate_openssl_class.h"

#define CONSTRUCT_CERTPOLICY_DATA_SIZE 1

using namespace std;

const int g_deviceTestCertSize = sizeof(g_deviceTestCert);

const int g_rootCertSize = sizeof(g_rootCert);

const int g_secondCertSize = sizeof(g_secondCert);

const int g_testInvalidCertSize = sizeof(g_testInvalidCert);
/* g_testSelfSignedCaCert
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 272 (0x110)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = CN, ST = BJ, L = BJ, O = HD, OU = dev, CN = ca, emailAddress = ca@cryptoframework.com
        Validity
            Not Before: Aug 19 12:49:06 2022 GMT
            Not After : Aug 16 12:49:06 2032 GMT
        Subject: C = CN, ST = BJ, L = BJ, O = HD, OU = dev, CN = ca, emailAddress = ca@cryptoframework.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:9f:29:d0:85:84:ed:6c:30:6e:d0:13:83:e0:1b:
                    61:08:f7:dd:63:41:06:4b:54:fb:f0:15:7f:e4:e5:
                    d5:a0:1a:e1:33:9e:5b:6f:d9:01:17:38:b1:dc:0b:
                    55:3c:5d:5c:28:a9:16:c7:ae:88:63:77:d2:1c:17:
                    ad:71:54:1e:b7:0c:7f:4c:36:b0:29:33:9c:95:59:
                    fe:b4:1c:7c:43:b9:29:bd:6f:07:3e:83:10:47:20:
                    21:26:04:86:1a:8e:05:f6:01:8a:de:6a:7e:9a:b9:
                    47:6f:b6:47:f4:e1:ff:26:d5:fa:40:6b:52:5f:86:
                    b2:c5:db:0c:07:ba:a1:90:b2:e7:a9:46:a6:10:ef:
                    98:73:14:3b:b6:b5:de:3f:92:16:64:e1:31:b2:36:
                    c9:ec:ae:6b:52:da:81:2a:1a:04:97:d8:d4:9f:a2:
                    ee:35:8f:9a:61:05:47:47:50:da:9d:04:1a:31:d3:
                    81:01:a1:46:8e:55:bb:00:c7:8a:93:52:bf:45:cf:
                    f0:e5:00:fc:f6:1b:2f:f4:81:8f:51:6a:e0:2d:e0:
                    b5:fb:e3:7a:cc:14:6f:35:5a:32:8a:bf:c0:2b:b2:
                    d6:a7:17:23:cd:19:2d:ed:f0:85:1d:b8:73:47:17:
                    60:53:b4:b8:68:bd:7a:03:e9:db:87:f0:ef:26:06:
                    aa:01
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                8C:A3:3B:42:63:01:B3:4D:51:F6:E4:2D:B5:83:7F:18:39:2F:B7:B5
            X509v3 Authority Key Identifier:
                keyid:8C:A3:3B:42:63:01:B3:4D:51:F6:E4:2D:B5:83:7F:18:39:2F:B7:B5

            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:2
            X509v3 Key Usage:
                Certificate Sign, CRL Sign
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Alternative Name:
                email:ca@cryptoframework.com
            X509v3 Issuer Alternative Name:
                email:ca@cryptoframework.com
    Signature Algorithm: sha256WithRSAEncryption
         87:ee:11:13:a7:09:eb:6f:e0:2d:8b:2c:2e:47:3b:11:28:3b:
         7b:12:b0:66:59:a2:b0:7c:81:89:cb:b2:ff:e5:da:80:e6:77:
         71:36:e0:40:d5:e5:42:86:4a:6f:0f:e4:b3:f0:7f:70:89:db:
         40:66:1b:a4:09:b8:ed:2b:9d:a3:e2:3f:1b:dc:63:d1:7e:e0:
         40:1f:70:b5:2a:db:4a:d3:ac:e9:28:e7:2e:26:14:d3:11:5c:
         16:c7:34:8f:a9:36:4a:b9:72:8b:04:50:72:34:b8:3c:e2:a2:
         51:2d:02:9b:71:77:0c:71:9d:8f:9e:4f:94:19:17:c6:e7:57:
         0a:ad:95:dc:9d:d5:c0:a7:f6:6d:58:d0:6f:3c:f6:f8:cf:d0:
         d6:6f:8f:ec:58:41:f8:99:9e:3b:c7:9e:9a:4a:8c:43:4b:45:
         31:4d:c4:33:8e:35:36:97:a3:0b:98:85:54:01:a0:a3:09:c2:
         f1:2d:01:f9:fc:47:f5:d0:49:b8:73:3a:be:9c:44:5b:0d:dc:
         91:91:43:65:0d:64:77:dd:58:46:0a:fb:8d:8f:1f:73:4b:ff:
         4f:4b:73:1d:66:ce:11:5c:e4:94:42:01:58:bd:66:a2:6a:4b:
         04:2c:1e:d3:f1:b0:f8:13:ba:d1:b7:e2:d8:ca:09:c3:cb:76:
         21:c0:75:43
*/

const int g_testSelfSignedCaCertSize = sizeof(g_testSelfSignedCaCert);

const int g_testSubjectAndIssuerNameDerDataSize =
    sizeof(g_testSubjectAndIssuerNameDerData) / sizeof(g_testSubjectAndIssuerNameDerData[0]);

const int g_testPublicKeyDerDataSize = sizeof(g_testPublicKeyDerData);

const int g_crlDerDataSize = sizeof(g_crlDerData);

const int g_testCrlSubAndIssNameDerDataSize =
    sizeof(g_testCrlSubAndIssNameDerData) / sizeof(g_testCrlSubAndIssNameDerData[0]);

const int g_testErrorCertSize = sizeof(g_testErrorCert);

const int g_testCertSize = sizeof(g_testCert);

const int g_testCrlSize = sizeof(g_testCrl);

const int g_testCrlWithoutExtsSize = sizeof(g_testCrlWithoutExts);

const int g_testCrlWithBignumSerialSize = sizeof(g_testCrlWithBignumSerial);

const int g_testCrlWhichEntryWithExtSize = sizeof(g_testCrlWhichEntryWithExt);

const int g_testCertChainPemSize = sizeof(g_testCertChainPem) / sizeof(char);

const int g_testCertChainPem163Size = sizeof(g_testCertChainPem163) / sizeof(char);

const int g_testOcspResponderCertSize = sizeof(g_testOcspResponderCert) / sizeof(char);

const int g_testCertChainPemMidSize = sizeof(g_testCertChainPemMid) / sizeof(char);

const int g_testCertChainPemMidCRLSize = sizeof(g_testCertChainPemMidCRL) / sizeof(char);

const int g_testCertChainPemRootSize = sizeof(g_testCertChainPemRoot) / sizeof(char);

const int g_testCertChainPemRoot163Size = sizeof(g_testCertChainPemRoot163) / sizeof(char);

const int g_testCertChainPemNoRootSize = sizeof(g_testCertChainPemNoRoot) / sizeof(char);

const int g_testCertChainPemNoRootHasPubKeySize = sizeof(g_testCertChainPemNoRootHasPubKey) / sizeof(char);

const int g_testCertChainPemNoRootLastSize = sizeof(g_testCertChainPemNoRootLast) / sizeof(char);

const int g_testChainDataP7bSize = sizeof(g_testChainDataP7b) / sizeof(g_testChainDataP7b[0]);

const int g_testChainDataDerSize = sizeof(g_testChainDataDer) / sizeof(g_testChainDataDer[0]);

const int g_testChainPubkeyPemRootDataSize =
    sizeof(g_testChainPubkeyPemRootData) / sizeof(g_testChainPubkeyPemRootData[0]);

const int g_testChainPubkeyPemRootHasPubKeySize =
    sizeof(g_testChainPubkeyPemRootHasPubKey) / sizeof(g_testChainPubkeyPemRootHasPubKey[0]);

const int g_testChainSubjectPemRootDataSize =
    sizeof(g_testChainSubjectPemRootData) / sizeof(g_testChainSubjectPemRootData[0]);

const int g_testChainSubjectPemOtherSubjectDataSize =
    sizeof(g_testChainSubjectPemOtherSubjectData) / sizeof(g_testChainSubjectPemOtherSubjectData[0]);

const int g_testIssuerCertSize = sizeof(g_testIssuerCert);

const int g_testCertChainPemDisorderSize = sizeof(g_testCertChainPemDisorder) / sizeof(char);

const int g_testChainPubkeyPemNoRootLastSize =
    sizeof(g_testChainPubkeyPemNoRootLast) / sizeof(g_testChainPubkeyPemNoRootLast[0]);

const int g_testChainSubjectPemNoRootLastUpSize =
    sizeof(g_testChainSubjectPemNoRootLastUp) / sizeof(g_testChainSubjectPemNoRootLastUp[0]);

const int g_testChainPubkeyPemNoRootLastUpSize =
    sizeof(g_testChainPubkeyPemNoRootLastUp) / sizeof(g_testChainPubkeyPemNoRootLastUp[0]);

const int g_testChainSubjectPemNoRootLastSize =
    sizeof(g_testChainSubjectPemNoRootLast) / sizeof(g_testChainSubjectPemNoRootLast[0]);

const CfEncodingBlob g_crlDerInStream = { const_cast<uint8_t *>(g_crlDerData), sizeof(g_crlDerData), CF_FORMAT_DER };

const CfEncodingBlob g_invalidCrlDerInStream = { const_cast<uint8_t *>(g_crlDerData), sizeof(g_crlDerData),
    (enum CfEncodingFormat)(-1) };

const CfEncodingBlob g_inStreamCrl = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCrl)), sizeof(g_testCrl),
    CF_FORMAT_PEM };

const CfEncodingBlob g_crlWithoutExtPemInStream = {
    reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCrlWithoutExts)), sizeof(g_testCrlWithoutExts), CF_FORMAT_PEM
};

const CfEncodingBlob g_crlWithBignumSerialInStream = { reinterpret_cast<uint8_t *>(
                                                           const_cast<char *>(g_testCrlWithBignumSerial)),
    sizeof(g_testCrlWithBignumSerial), CF_FORMAT_PEM };

const CfEncodingBlob g_crlWhichEntryWithExtInStream = { reinterpret_cast<uint8_t *>(
                                                            const_cast<char *>(g_testCrlWhichEntryWithExt)),
    sizeof(g_testCrlWhichEntryWithExt), CF_FORMAT_PEM };

const CfEncodingBlob g_inStreamCert = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCert)), sizeof(g_testCert),
    CF_FORMAT_PEM };

const CfEncodingBlob g_inStreamSelfSignedCaCert = {
    reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert)), g_testSelfSignedCaCertSize, CF_FORMAT_PEM
};

const CfEncodingBlob g_inStreamIssuerCert = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testIssuerCert)),
    sizeof(g_testIssuerCert), CF_FORMAT_PEM };

const CfEncodingBlob g_inStreamChainDataP7b = { const_cast<uint8_t *>(g_testChainDataP7b), g_testChainDataP7bSize,
    CF_FORMAT_PKCS7 };

const CfEncodingBlob g_inStreamChainDataDer = { const_cast<uint8_t *>(g_testChainDataDer), g_testChainDataDerSize,
    CF_FORMAT_DER };

const CfEncodingBlob g_inStreamChainDataPem = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPem)),
    g_testCertChainPemSize, CF_FORMAT_PEM };

const CfEncodingBlob g_inStreamChainDataPem163 = {
    reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPem163)), g_testCertChainPem163Size, CF_FORMAT_PEM
};

const CfEncodingBlob g_inStreamOcspResponderCert = {
    reinterpret_cast<uint8_t *>(const_cast<char *>(g_testOcspResponderCert)), g_testOcspResponderCertSize, CF_FORMAT_PEM
};

const CfEncodingBlob g_inStreamChainDataPemMid = {
    reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMid)), g_testCertChainPemMidSize, CF_FORMAT_PEM
};

const CfEncodingBlob g_inStreamChainDataPemRoot = {
    reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemRoot)), g_testCertChainPemRootSize, CF_FORMAT_PEM
};

const CfEncodingBlob g_inStreamChainDataPemRoot163 = { reinterpret_cast<uint8_t *>(
                                                           const_cast<char *>(g_testCertChainPemRoot163)),
    g_testCertChainPemRoot163Size, CF_FORMAT_PEM };

const CfEncodingBlob g_inStreamChainDataPemNoRoot = { reinterpret_cast<uint8_t *>(
                                                          const_cast<char *>(g_testCertChainPemNoRoot)),
    g_testCertChainPemNoRootSize, CF_FORMAT_PEM };

const CfEncodingBlob g_inStreamChainDataPemMidCRL = { reinterpret_cast<uint8_t *>(
                                                          const_cast<char *>(g_testCertChainPemMidCRL)),
    g_testCertChainPemMidCRLSize, CF_FORMAT_PEM };

const CfEncodingBlob g_inStreamChainPemNoRootHasPubKey = { reinterpret_cast<uint8_t *>(
                                                               const_cast<char *>(g_testCertChainPemNoRootHasPubKey)),
    g_testCertChainPemNoRootHasPubKeySize, CF_FORMAT_PEM };

const CfEncodingBlob g_inStreamChainPemNoRootLast = { reinterpret_cast<uint8_t *>(
                                                          const_cast<char *>(g_testCertChainPemNoRootLast)),
    g_testCertChainPemNoRootLastSize, CF_FORMAT_PEM };

const CfEncodingBlob g_inStreamChainDataPemDisorder = { reinterpret_cast<uint8_t *>(
                                                            const_cast<char *>(g_testCertChainPemDisorder)),
    g_testCertChainPemDisorderSize, CF_FORMAT_PEM };

const char *GetInvalidCertClass(void)
{
    return "INVALID_CERT_CLASS";
}

const char *GetInvalidCrlClass(void)
{
    return "INVALID_CRL_CLASS";
}

SubAltNameArray *ConstructSubAltNameArrayData()
{
    SubAltNameArray *newSANArr = static_cast<SubAltNameArray *>(CfMalloc(sizeof(SubAltNameArray), 0));
    if (newSANArr == nullptr) {
        CF_LOG_E("Failed to allocate newSANArr memory!");
        return nullptr;
    }

    newSANArr->count = TEST_SUBJECT_ALTERNATIVE_NAMES_SIZE;
    newSANArr->data =
        static_cast<SubjectAlternaiveNameData *>(CfMalloc(newSANArr->count * sizeof(SubjectAlternaiveNameData), 0));
    if (newSANArr->data == nullptr) {
        CF_LOG_E("Failed to allocate data memory!");
        CfFree(newSANArr);
        return nullptr;
    }

    for (uint32_t i = 0; i < newSANArr->count; i++) {
        newSANArr->data[i].type = (CfGeneralNameType)GEN_DNS;
        newSANArr->data[i].name.data = const_cast<uint8_t *>(g_testSubjectAlternativeNames[i].data);
        newSANArr->data[i].name.size = g_testSubjectAlternativeNames[i].size;
    }

    return newSANArr;
}

CfArray *ConstructCertPolicyData()
{
    CfArray *newBlobArr = static_cast<CfArray *>(CfMalloc(sizeof(CfArray), 0));
    if (newBlobArr == nullptr) {
        CF_LOG_E("Failed to allocate newBlobArr memory!");
        return nullptr;
    }

    newBlobArr->count = CONSTRUCT_CERTPOLICY_DATA_SIZE;
    newBlobArr->format = CF_FORMAT_DER;
    newBlobArr->data = static_cast<CfBlob *>(CfMalloc(newBlobArr->count * sizeof(CfBlob), 0));
    if (newBlobArr->data == nullptr) {
        CF_LOG_E("Failed to allocate data memory!");
        CfFree(newBlobArr);
        return nullptr;
    }

    newBlobArr->data[0].data = const_cast<uint8_t *>(g_testCertPolicy);
    newBlobArr->data[0].size = sizeof(g_testCertPolicy);

    return newBlobArr;
}

const char *GetValidCrlClass(void)
{
    return X509_CRL_OPENSSL_CLASS;
}

const char *GetValidX509CertificateClass(void)
{
    return HCF_X509_CERTIFICATE_CLASS;
}

void FreeTrustAnchor(HcfX509TrustAnchor *&trustAnchor)
{
    if (trustAnchor == nullptr) {
        return;
    }
    CfBlobFree(&trustAnchor->CAPubKey);
    CfBlobFree(&trustAnchor->CASubject);
    CfObjDestroy(trustAnchor->CACert);
    trustAnchor->CACert = nullptr;
    CfFree(trustAnchor);
    trustAnchor = nullptr;
}

void BuildAnchorArr(const CfEncodingBlob &certInStream, HcfX509TrustAnchorArray &trustAnchorArray)
{
    HcfX509TrustAnchor *anchor = static_cast<HcfX509TrustAnchor *>(CfMalloc(sizeof(HcfX509TrustAnchor), 0));
    ASSERT_NE(anchor, nullptr);

    (void)HcfX509CertificateCreate(&certInStream, &anchor->CACert);
    trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
    ASSERT_NE(trustAnchorArray.data, nullptr);
    trustAnchorArray.data[0] = anchor;
    trustAnchorArray.count = 1;
}

void FreeTrustAnchorArr(HcfX509TrustAnchorArray &trustAnchorArray)
{
    for (uint32_t i = 0; i < trustAnchorArray.count; ++i) {
        HcfX509TrustAnchor *anchor = trustAnchorArray.data[i];
        FreeTrustAnchor(anchor);
    }
    CfFree(trustAnchorArray.data);
    trustAnchorArray.data = nullptr;
    trustAnchorArray.count = 0;
}

void BuildCollectionArr(const CfEncodingBlob *certInStream, const CfEncodingBlob *crlInStream,
    HcfCertCRLCollectionArray &certCRLCollections)
{
    CfResult ret = CF_SUCCESS;
    HcfX509CertificateArray *certArray = nullptr;
    if (certInStream != nullptr) {
        certArray = static_cast<HcfX509CertificateArray *>(CfMalloc(sizeof(HcfX509CertificateArray), 0));
        ASSERT_NE(certArray, nullptr);

        HcfX509Certificate *x509CertObj = nullptr;
        (void)HcfX509CertificateCreate(certInStream, &x509CertObj);
        ASSERT_NE(x509CertObj, nullptr);

        certArray->data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
        ASSERT_NE(certArray->data, nullptr);
        certArray->data[0] = x509CertObj;
        certArray->count = 1;
    }

    HcfX509CrlArray *crlArray = nullptr;
    if (crlInStream != nullptr) {
        crlArray = static_cast<HcfX509CrlArray *>(CfMalloc(sizeof(HcfX509CrlArray), 0));
        ASSERT_NE(crlArray, nullptr);

        HcfX509Crl *x509Crl = nullptr;
        ret = HcfX509CrlCreate(crlInStream, &x509Crl);
        ASSERT_EQ(ret, CF_SUCCESS);
        ASSERT_NE(x509Crl, nullptr);

        crlArray->data = static_cast<HcfX509Crl **>(CfMalloc(1 * sizeof(HcfX509Crl *), 0));
        ASSERT_NE(crlArray->data, nullptr);
        crlArray->data[0] = x509Crl;
        crlArray->count = 1;
    }

    HcfCertCrlCollection *x509CertCrlCollection = nullptr;
    ret = HcfCertCrlCollectionCreate(certArray, crlArray, &x509CertCrlCollection);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509CertCrlCollection, nullptr);

    certCRLCollections.data = static_cast<HcfCertCrlCollection **>(CfMalloc(1 * sizeof(HcfCertCrlCollection *), 0));
    ASSERT_NE(certCRLCollections.data, nullptr);
    certCRLCollections.data[0] = x509CertCrlCollection;
    certCRLCollections.count = 1;

    FreeCertArrayData(certArray);
    CfFree(certArray);
    FreeCrlArrayData(crlArray);
    CfFree(crlArray);
}

void FreeCertCrlCollectionArr(HcfCertCRLCollectionArray &certCRLCollections)
{
    for (uint32_t i = 0; i < certCRLCollections.count; ++i) {
        HcfCertCrlCollection *collection = certCRLCollections.data[i];
        CfObjDestroy(collection);
    }
    CfFree(certCRLCollections.data);
    certCRLCollections.data = nullptr;
    certCRLCollections.count = 0;
}

void FreeValidateResult(HcfX509CertChainValidateResult &result)
{
    if (result.entityCert != nullptr) {
        CfObjDestroy(result.entityCert);
        result.entityCert = nullptr;
    }

    if (result.trustAnchor != nullptr) {
        FreeTrustAnchor(result.trustAnchor);
    }
}
