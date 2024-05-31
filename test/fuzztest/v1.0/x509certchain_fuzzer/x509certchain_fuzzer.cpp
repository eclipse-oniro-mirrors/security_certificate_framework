/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "x509certchain_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "securec.h"

#include "crypto_x509_cert_chain_data_p7b.h"
#include "crypto_x509_cert_chain_data_der.h"
#include "crypto_x509_cert_chain_data_pem.h"
#include "crypto_x509_cert_chain_data_pem_added.h"
#include "crypto_x509_cert_chain_data_pem_ex.h"
#include "x509_cert_chain_validate_params.h"
#include "x509_cert_chain_validate_result.h"
#include "crypto_x509_test_common.h"
#include "x509_trust_anchor.h"
#include "x509_cert_chain_openssl.h"

#include "cf_blob.h"
#include "cf_result.h"
#include "x509_certificate.h"
#include "x509_cert_chain.h"
#include "cert_chain_validator.h"

namespace OHOS {
    constexpr int32_t CERT_HEADER_LEN = 2;
    constexpr int32_t CERT_COUNT = 3;
    constexpr int32_t MAX_DEPTH = 100;
    static bool g_testCertChainFlag = true;
    static bool g_testCertChainValidatorFlag = true;
    static bool g_testCertChainBuildResultFlag = true;
    static bool g_testCreateTrustAnchorFlag = true;

    const CfEncodingBlob g_inStreamChainDataP7b = { const_cast<uint8_t *>(g_testChainDataP7b),
        sizeof(g_testChainDataP7b) / sizeof(g_testChainDataP7b[0]),
        CF_FORMAT_PKCS7 };

    const CfEncodingBlob g_inStreamChainDataDer = { const_cast<uint8_t *>(g_testChainDataDer),
        sizeof(g_testChainDataDer) / sizeof(g_testChainDataDer[0]),
        CF_FORMAT_DER };

    const CfEncodingBlob g_inStreamChainDataPem = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPem)),
        sizeof(g_testCertChainPem) / sizeof(g_testCertChainPem[0]), CF_FORMAT_PEM };

    const CfEncodingBlob g_inStreamChainDataPemRoot = {
        reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemRoot)),
        sizeof(g_testCertChainPemRoot) / sizeof(g_testCertChainPemRoot[0]),
        CF_FORMAT_PEM };

    static CfResult TestGetCertList(HcfCertChain *certChain)
    {
        HcfX509CertificateArray certs = {nullptr, 0};
        CfResult ret = certChain->getCertList(certChain, &certs);
        if (ret != CF_SUCCESS) {
            return ret;
        }
        if (certs.count != CERT_COUNT) {
            return CF_INVALID_PARAMS;
        }
    
        return CF_SUCCESS;
    }

    static CfResult BuildAnchorArr1(const CfEncodingBlob &certInStream, HcfX509TrustAnchorArray &trustAnchorArray)
    {
        HcfX509TrustAnchor *anchor = static_cast<HcfX509TrustAnchor *>(CfMalloc(sizeof(HcfX509TrustAnchor), 0));
        if (anchor == nullptr) {
            return CF_ERR_MALLOC;
        }

        (void)HcfX509CertificateCreate(&certInStream, &anchor->CACert);
        trustAnchorArray.data = static_cast<HcfX509TrustAnchor **>(CfMalloc(1 * sizeof(HcfX509TrustAnchor *), 0));
        if (trustAnchorArray.data == nullptr) {
            CfFree(anchor);
            return CF_ERR_MALLOC;
        }
        trustAnchorArray.data[0] = anchor;
        trustAnchorArray.count = 1;
        return CF_SUCCESS;
    }

    static void FreeTrustAnchor1(HcfX509TrustAnchor *&trustAnchor)
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

    static void FreeTrustAnchorArr1(HcfX509TrustAnchorArray &trustAnchorArray)
    {
        for (uint32_t i = 0; i < trustAnchorArray.count; ++i) {
            HcfX509TrustAnchor *anchor = trustAnchorArray.data[i];
            FreeTrustAnchor1(anchor);
        }
        CfFree(trustAnchorArray.data);
        trustAnchorArray.data = nullptr;
        trustAnchorArray.count = 0;
    }

    static CfResult TestVerify(HcfCertChain *certChain)
    {
        HcfX509CertChainValidateResult result = { 0 };
        HcfX509TrustAnchorArray trustAnchorArray = { 0 };
        CfResult ret = BuildAnchorArr1(g_inStreamChainDataPemRoot, trustAnchorArray);
        if (ret != CF_SUCCESS) {
            return ret;
        }

        HcfX509CertChainValidateParams pCertChainValidateParams = { 0 };
        const char *date = "20231212080000Z";
        CfBlob validDate = { 0 };
        validDate.data = reinterpret_cast<uint8_t *>(const_cast<char *>(date));
        validDate.size = strlen(date) + 1;
        pCertChainValidateParams.date = &validDate;
        pCertChainValidateParams.trustAnchors = &trustAnchorArray;

        ret = certChain->validate(certChain, &pCertChainValidateParams, &result);
        FreeTrustAnchorArr1(trustAnchorArray);
        return ret;
    }

    static const char *GetInvalidCertChainClass(void)
    {
        return "HcfInvalidCertChain";
    }

    static void TestToString(HcfCertChain *certChain)
    {
        CfBlob blob = { 0, nullptr };
        (void)certChain->toString(certChain, &blob);
        CfBlobDataFree(&blob);

        HcfCertChain testCertChain = {};
        testCertChain.base.getClass = GetInvalidCertChainClass;
        (void)certChain->toString(&testCertChain, &blob);
        (void)certChain->toString(nullptr, &blob);
        (void)certChain->toString(certChain, nullptr);
        (void)certChain->toString(nullptr, nullptr);
    }

    static void TestHashCode(HcfCertChain *certChain)
    {
        CfBlob blob = { 0, nullptr };
        (void)certChain->hashCode(certChain, &blob);
        CfBlobDataFree(&blob);

        HcfCertChain testCertChain = {};
        testCertChain.base.getClass = GetInvalidCertChainClass;
        (void)certChain->hashCode(&testCertChain, &blob);
        (void)certChain->hashCode(nullptr, &blob);
        (void)certChain->hashCode(certChain, nullptr);
        (void)certChain->hashCode(nullptr, nullptr);
    }

    static CfResult CreateOneCertChainCore(const CfEncodingBlob *inStream)
    {
        HcfCertChain *certChain = nullptr;
        CfResult ret = HcfCertChainCreate(inStream, nullptr, &certChain);
        if (ret != CF_SUCCESS) {
            return ret;
        }
        ret = TestGetCertList(certChain);
        if (ret != CF_SUCCESS) {
            CfObjDestroy(certChain);
            return ret;
        }

        (void)TestToString(certChain);
        (void)TestHashCode(certChain);
        (void)TestVerify(certChain);
        CfObjDestroy(certChain);
        return ret;
    }

    static void CreateChainByArr()
    {
        HcfX509CertChainSpi *certChainSpi = nullptr;
        HcfX509CertificateArray certArray;
        HcfX509Certificate *x509CertObj = nullptr;

        int certSize = sizeof(g_testSelfSignedCaCert);
        const CfEncodingBlob cert = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCert)),
            certSize, CF_FORMAT_PEM };
        (void)HcfX509CertificateCreate(&cert, &x509CertObj);

        certArray.data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
        if (certArray.data == nullptr) {
            return;
        }
        certArray.data[0] = x509CertObj;
        certArray.count = 1;

        (void)HcfX509CertChainByArrSpiCreate(nullptr, &certChainSpi);
        (void)HcfX509CertChainByArrSpiCreate(&certArray, nullptr);
        (void)HcfX509CertChainByArrSpiCreate(&certArray, &certChainSpi);

        CfFree(certArray.data);
        CfObjDestroy(x509CertObj);
        CfObjDestroy(certChainSpi);
    }

    static void FreeHcfRevocationCheckParam1(HcfRevocationCheckParam *param)
    {
        if (param == nullptr) {
            return;
        }

        if (param->options != nullptr) {
            if (param->options->data != nullptr) {
                CfFree(param->options->data);
            }

            CfFree(param->options);
        }

        if (param->ocspResponses != nullptr) {
            CfFree(param->ocspResponses);
        }

        if (param->ocspResponderCert != nullptr) {
            CfObjDestroy(param->ocspResponderCert);
        }

        CfFree(param);
    }

    static HcfRevocationCheckParam *ConstructHcfRevocationCheckParam1(const HcfRevChkOption *data, size_t size,
        CfBlob *ocspResponderURI = NULL, CfBlob *crlDownloadURI = NULL,
        const CfEncodingBlob *ocspResponderCertStream = NULL)
    {
        HcfRevChkOpArray *revChkOpArray = static_cast<HcfRevChkOpArray *>(CfMalloc(sizeof(HcfRevChkOpArray), 0));
        if (revChkOpArray == nullptr) {
            return nullptr;
        }

        revChkOpArray->count = size;
        revChkOpArray->data =
            static_cast<HcfRevChkOption *>(CfMalloc(revChkOpArray->count * sizeof(HcfRevChkOption), 0));
        if (revChkOpArray->data == nullptr) {
            CfFree(revChkOpArray);
            return nullptr;
        }

        for (size_t i = 0; i < revChkOpArray->count; i++) {
            revChkOpArray->data[i] = data[i];
        }

        CfBlob *resp = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (resp == nullptr) {
            CfFree(revChkOpArray->data);
            CfFree(revChkOpArray);
            return nullptr;
        }
        resp->data = (uint8_t *)(&g_testOcspResponses[0]);
        resp->size = sizeof(g_testOcspResponses);

        HcfRevocationCheckParam *param =
            static_cast<HcfRevocationCheckParam *>(CfMalloc(sizeof(HcfRevocationCheckParam), 0));
        if (param == nullptr) {
            CfFree(revChkOpArray->data);
            CfFree(revChkOpArray);
            return nullptr;
        }

        param->options = revChkOpArray;
        param->ocspResponses = resp;
        param->ocspResponderURI = ocspResponderURI;
        param->crlDownloadURI = crlDownloadURI;

        if (ocspResponderCertStream != NULL) {
            (void)HcfX509CertificateCreate(&g_inStreamOcspResponderCert, &(param->ocspResponderCert));
            if (param->ocspResponderCert == nullptr) {
                FreeHcfRevocationCheckParam1(param);
                return nullptr;
            }
        }

        return param;
    }

    void FreeValidateResult1(HcfX509CertChainValidateResult &result)
    {
        if (result.entityCert != nullptr) {
            CfObjDestroy(result.entityCert);
            result.entityCert = nullptr;
        }

        if (result.trustAnchor != nullptr) {
            FreeTrustAnchor1(result.trustAnchor);
        }
    }

    static void TestEngineValidateInvalid(HcfX509CertChainSpi *spi, const CfEncodingBlob *inStream)
    {
        HcfX509TrustAnchorArray trustAnchorArray = { 0 };
        if (BuildAnchorArr1(*inStream, trustAnchorArray) != CF_SUCCESS) {
            return;
        }
        HcfX509CertChainValidateParams params = { 0 };
        params.trustAnchors = &trustAnchorArray;
        HcfX509CertChainValidateResult result = { 0 };

        params.policy = (HcfValPolicyType)-1;
        (void)spi->engineValidate(spi, &params, &result);

        params.policy = VALIDATION_POLICY_TYPE_SSL;
        (void)spi->engineValidate(spi, &params, &result);

        FreeTrustAnchorArr1(trustAnchorArray);
    }

    static void TestEngineValidate(HcfX509CertChainSpi *spi, const CfEncodingBlob *inStream)
    {
        HcfX509TrustAnchorArray trustAnchorArray = { 0 };
        if (BuildAnchorArr1(*inStream, trustAnchorArray) != CF_SUCCESS) {
            return;
        }
        HcfX509CertChainValidateParams params = { 0 };
        params.trustAnchors = &trustAnchorArray;

        HcfRevChkOption data[] = { REVOCATION_CHECK_OPTION_PREFER_OCSP };
        params.revocationCheckParam = ConstructHcfRevocationCheckParam1(data, sizeof(data) / sizeof(data[0]));
        if (params.revocationCheckParam == nullptr) {
            return;
        }

        HcfX509CertChainValidateResult result = { 0 };
        spi->engineValidate(spi, &params, &result);

        FreeValidateResult1(result);
        FreeTrustAnchorArr1(trustAnchorArray);
        FreeHcfRevocationCheckParam1(params.revocationCheckParam);
    }

    static void CreateChainByEnc()
    {
        int pemSize = sizeof(g_testCertChainPem) / sizeof(char);
        int pem163Size = sizeof(g_testCertChainPem163) / sizeof(char);
        const CfEncodingBlob pem = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPem)),
            pemSize, CF_FORMAT_PEM };
        const CfEncodingBlob pem163 = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPem163)),
            pem163Size, CF_FORMAT_PEM };
        HcfX509CertChainSpi *certChainSpi = nullptr;
        CfResult ret = HcfX509CertChainByEncSpiCreate(&pem, &certChainSpi);
        if (ret != CF_SUCCESS) {
            return;
        }
        HcfX509CertChainSpi *certChainPemSpi = certChainSpi;

        certChainSpi = nullptr;
        ret = HcfX509CertChainByEncSpiCreate(&pem163, &certChainSpi);
        if (ret != CF_SUCCESS) {
            CfObjDestroy(certChainPemSpi);
            return;
        }
        HcfX509CertChainSpi *certChainPemSpi163 = certChainSpi;

        int pemRootSize = sizeof(g_testCertChainPemRoot) / sizeof(char);
        int pemRoot163Size = sizeof(g_testCertChainPemRoot163) / sizeof(char);
        const CfEncodingBlob inpemRoot = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemRoot)),
            pemRootSize, CF_FORMAT_PEM };
        const CfEncodingBlob inpemRoot163 = {
            reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemRoot163)),
            pemRoot163Size, CF_FORMAT_PEM };
        TestEngineValidateInvalid(certChainPemSpi, &inpemRoot);
        TestEngineValidateInvalid(certChainPemSpi163, &inpemRoot163);
        TestEngineValidate(certChainPemSpi163, &inpemRoot163);

        CfObjDestroy(certChainPemSpi);
        CfObjDestroy(certChainPemSpi163);
    }

    static CfResult CreateOneCertChain(CfEncodingFormat encodingFormat)
    {
        CreateChainByArr();
        CreateChainByEnc();
        switch (encodingFormat) {
            case CF_FORMAT_DER:
                return CreateOneCertChainCore(&g_inStreamChainDataDer);
            case CF_FORMAT_PKCS7:
                return CreateOneCertChainCore(&g_inStreamChainDataP7b);
            case CF_FORMAT_PEM:
                return CreateOneCertChainCore(&g_inStreamChainDataPem);
            default:
                return CF_INVALID_PARAMS;
        }
    }

    void X509CertChainFuzzTest(const uint8_t* data, size_t size, CfEncodingFormat encodingFormat)
    {
        if (g_testCertChainFlag) {
            if (CreateOneCertChain(encodingFormat) != CF_SUCCESS) {
                return;
            }
            g_testCertChainFlag = false;
        }
        if (data == nullptr) {
            return;
        }
        CfEncodingBlob inStream = { 0 };
        inStream.data = const_cast<uint8_t *>(data);
        inStream.encodingFormat = encodingFormat;
        inStream.len = size;
        HcfCertChain *x509CertObj = nullptr;
        CfResult res = HcfCertChainCreate(&inStream, nullptr, &x509CertObj);
        if (res != CF_SUCCESS) {
            return;
        }
        CfObjDestroy(x509CertObj);
        return;
    }

    static CfResult ConstructCertData(HcfCertChainData *certsData)
    {
        certsData->format = CF_FORMAT_PEM;
        certsData->count = 2; /* level-2 cert chain. */
        uint32_t caCertLen = strlen(g_testCertChainValidatorCaCert) + 1;
        uint32_t secondCaCertLen = strlen(g_testCertChainValidatorSecondCaCert) + 1;
        certsData->dataLen = CERT_HEADER_LEN + secondCaCertLen + CERT_HEADER_LEN + caCertLen;
        certsData->data = static_cast<uint8_t *>(malloc(certsData->dataLen));
        if (certsData->data == nullptr) {
            return CF_ERR_MALLOC;
        }
        if (memcpy_s(certsData->data, CERT_HEADER_LEN + secondCaCertLen + CERT_HEADER_LEN + caCertLen,
            &secondCaCertLen, CERT_HEADER_LEN) != EOK) {
            goto OUT;
        }
        if (memcpy_s(certsData->data + CERT_HEADER_LEN, secondCaCertLen + CERT_HEADER_LEN + caCertLen,
            g_testCertChainValidatorSecondCaCert, secondCaCertLen) != EOK) {
            goto OUT;
        }
        if (memcpy_s(certsData->data + CERT_HEADER_LEN + secondCaCertLen, CERT_HEADER_LEN + caCertLen,
            &caCertLen, CERT_HEADER_LEN) != EOK) {
            goto OUT;
        }
        if (memcpy_s(certsData->data + CERT_HEADER_LEN + secondCaCertLen + CERT_HEADER_LEN, caCertLen,
            g_testCertChainValidatorCaCert, caCertLen) != EOK) {
            goto OUT;
        }
        return CF_SUCCESS;

    OUT:
        free(certsData->data);
        certsData->data = nullptr;
        return CF_INVALID_PARAMS;
    }

    static void FreeCertData(HcfCertChainData *certsData)
    {
        if (certsData != nullptr && certsData->data != nullptr) {
            free(certsData->data);
        }
    }

    static CfResult CreateOneCertChainValidator()
    {
        HcfCertChainData certsData = {};
        ConstructCertData(&certsData);
        HcfCertChainValidator *pathValidator = nullptr;
        (void)HcfCertChainValidatorCreate("invalidPKIX", &pathValidator);
        (void)HcfCertChainValidatorCreate("PKIX", nullptr);
        CfResult res = HcfCertChainValidatorCreate("PKIX", &pathValidator);
        if (res != CF_SUCCESS) {
            goto OUT;
        }
        res = pathValidator->validate(pathValidator, &certsData);
        if (res != CF_SUCCESS) {
            goto OUT;
        }
        (void)pathValidator->getAlgorithm(pathValidator);
        (void)pathValidator->getAlgorithm(nullptr);
    OUT:
        FreeCertData(&certsData);
        CfObjDestroy(pathValidator);
        return res;
    }

    void X509CertChainValidatorCreateFuzzTest(const uint8_t* data, size_t size, CfEncodingFormat certFormat)
    {
        if (g_testCertChainValidatorFlag) {
            (void)CreateOneCertChainValidator();
            g_testCertChainValidatorFlag = false;
        }
        if (data == nullptr || size < sizeof(uint32_t)) {
            return;
        }
        HcfCertChainData certsData = {};
        certsData.format = certFormat;
        certsData.count = *reinterpret_cast<const uint32_t *>(data); /* level-2 cert chain. */
        certsData.dataLen = size;
        certsData.data = const_cast<uint8_t *>(data);
        HcfCertChainValidator *pathValidator = nullptr;
        CfResult res = HcfCertChainValidatorCreate("PKIX", &pathValidator);
        if (res != CF_SUCCESS) {
            return;
        }
        CfObjDestroy(pathValidator);
        return;
    }

    static void FreeCertArrayData(HcfX509CertificateArray *certs)
    {
        if (certs == nullptr) {
            return;
        }
        for (uint32_t i = 0; i < certs->count; ++i) {
            CfObjDestroy(certs->data[i]);
        }
        CfFree(certs->data);
        certs->data = nullptr;
        certs->count = 0;
    }

    static CfResult BuildCollectionArrNoCRL(const CfEncodingBlob *certInStream,
        HcfCertCRLCollectionArray &certCRLCollections)
    {
        CfResult ret = CF_ERR_MALLOC;
        HcfX509CertificateArray *certArray = nullptr;
        HcfCertCrlCollection *x509CertCrlCollection = nullptr;
        if (certInStream != nullptr) {
            certArray = static_cast<HcfX509CertificateArray *>(CfMalloc(sizeof(HcfX509CertificateArray), 0));
            if (certArray == nullptr) {
                goto Exit;
            }

            HcfX509Certificate *x509CertObj = nullptr;
            (void)HcfX509CertificateCreate(certInStream, &x509CertObj);
            if (x509CertObj == nullptr) {
                goto Exit;
            }

            certArray->data = static_cast<HcfX509Certificate **>(CfMalloc(1 * sizeof(HcfX509Certificate *), 0));
            if (certArray->data == nullptr) {
                goto Exit;
            }
            certArray->data[0] = x509CertObj;
            certArray->count = 1;
        }

        ret = HcfCertCrlCollectionCreate(certArray, nullptr, &x509CertCrlCollection);
        if (ret != CF_SUCCESS) {
            goto Exit;
        }

        certCRLCollections.data = static_cast<HcfCertCrlCollection **>(CfMalloc(1 * sizeof(HcfCertCrlCollection *),
            0));
        if (certCRLCollections.data == nullptr) {
            goto Exit;
        }
        certCRLCollections.data[0] = x509CertCrlCollection;
        certCRLCollections.count = 1;

        FreeCertArrayData(certArray);
        CfFree(certArray);
        return CF_SUCCESS;
    Exit:
        FreeCertArrayData(certArray);
        CfFree(certArray);
        CfFree(certCRLCollections.data);
        CfObjDestroy(x509CertCrlCollection);
        return ret;
    }

    static void FreeCertCrlCollectionArr1(HcfCertCRLCollectionArray &certCRLCollections)
    {
        for (uint32_t i = 0; i < certCRLCollections.count; ++i) {
            HcfCertCrlCollection *collection = certCRLCollections.data[i];
            CfObjDestroy(collection);
        }
        CfFree(certCRLCollections.data);
        certCRLCollections.data = nullptr;
        certCRLCollections.count = 0;
    }

    static CfResult BuildX509CertMatchParamsDataNoCRL(const CfEncodingBlob *certInStream,
        HcfX509CertChainValidateParams *params)
    {
        HcfCertCRLCollectionArray *certCRLCollections = nullptr;
        CfResult ret = CF_ERR_MALLOC;
        CfBlob *blob = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
        if (blob == nullptr) {
            return CF_ERR_MALLOC;
        }
        blob->data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testUpdateDateTime));
        blob->size = strlen(g_testUpdateDateTime) + 1;
        params->date = blob;

        HcfX509TrustAnchorArray *trustAnchorArray =
            static_cast<HcfX509TrustAnchorArray *>(CfMalloc(sizeof(HcfX509TrustAnchorArray), 0));
        if (trustAnchorArray == nullptr) {
            goto Exit;
        }
        ret = BuildAnchorArr1(*certInStream, *trustAnchorArray);
        if (ret != CF_SUCCESS) {
            goto Exit;
        }

        certCRLCollections = static_cast<HcfCertCRLCollectionArray *>(CfMalloc(sizeof(HcfCertCRLCollectionArray), 0));
        if (certCRLCollections == nullptr) {
            goto Exit;
        }
        ret = BuildCollectionArrNoCRL(certInStream, *certCRLCollections);
        if (ret != CF_SUCCESS) {
            goto Exit;
        }
        params->trustAnchors = trustAnchorArray;
        params->certCRLCollections = certCRLCollections;
        return CF_SUCCESS;
    Exit:
        CfFree(blob);
        FreeTrustAnchorArr1(*trustAnchorArray);
        CfFree(trustAnchorArray);
        CfFree(certCRLCollections);
        return ret;
    }

    static void FreeX509CertMatchParamsData(HcfX509CertChainValidateParams *params)
    {
        if (params == nullptr) {
            return;
        }

        if (params->date != nullptr) {
            CfFree(params->date);
            params->date = nullptr;
        }

        if (params->trustAnchors != nullptr) {
            FreeTrustAnchorArr1(*(params->trustAnchors));
            CfFree(params->trustAnchors);
            params->trustAnchors = nullptr;
        }

        if (params->certCRLCollections != nullptr) {
            FreeCertCrlCollectionArr1(*(params->certCRLCollections));
            CfFree(params->certCRLCollections);
            params->certCRLCollections = nullptr;
        }
    }

    static void FreeTrustAnchorData(HcfX509TrustAnchor *trustAnchor)
    {
        if (trustAnchor == NULL) {
            return;
        }
        CfBlobFree(&trustAnchor->CAPubKey);
        CfBlobFree(&trustAnchor->CASubject);
        CfObjDestroy(trustAnchor->CACert);
        trustAnchor->CACert = NULL;
    }

    static void FreeHcfX509CertChainBuildResult(HcfX509CertChainBuildResult *result)
    {
        if (result == nullptr) {
            return;
        }

        CfObjDestroy(result->certChain);
        CfFree(result);
    }

    static CfResult CreateOneCertChainBuildResultCreate()
    {
        HcfX509CertChainBuildParameters inParams = {};
        HcfX509CertChainBuildResult *returnObj = nullptr;
        CfEncodingBlob inStream = { 0 };
        HcfCertChain *certChain = nullptr;
        inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCertValid));
        inStream.encodingFormat = CF_FORMAT_PEM;
        inStream.len = strlen(g_testSelfSignedCaCertValid) + 1;

        CfResult ret = BuildX509CertMatchParamsDataNoCRL(&inStream, &inParams.validateParameters);
        if (ret != CF_SUCCESS) {
            goto Exit;
        }

        inParams.maxlength = MAX_DEPTH;

        CfBlob issue;
        issue.data = const_cast<uint8_t *>(g_testIssuerValid);
        issue.size = sizeof(g_testIssuerValid);
        inParams.certMatchParameters.issuer = &issue;
        inParams.certMatchParameters.minPathLenConstraint = -1;

        ret = HcfCertChainBuildResultCreate(&inParams, &returnObj);
        if (ret != CF_SUCCESS) {
            goto Exit;
        }
        certChain = returnObj->certChain;
        ret = certChain->validate(certChain, &inParams.validateParameters, &returnObj->validateResult);
        if (ret != CF_SUCCESS) {
            goto Exit;
        }

    Exit:
        if (returnObj != nullptr) {
            FreeTrustAnchorData(returnObj->validateResult.trustAnchor);
            CF_FREE_PTR(returnObj->validateResult.trustAnchor);
            CfObjDestroy(returnObj->validateResult.entityCert);
            FreeHcfX509CertChainBuildResult(returnObj);
        }

        FreeX509CertMatchParamsData(&inParams.validateParameters);
        return ret;
    }

    void X509BuildResultCreateFuzzTest(const uint8_t* data, size_t size, CfEncodingFormat certFormat)
    {
        if (g_testCertChainBuildResultFlag) {
            (void)CreateOneCertChainBuildResultCreate();
            g_testCertChainBuildResultFlag = false;
        }
        const char *date = "20231212080000Z";
        if (data == nullptr || size < sizeof(int32_t) || size < (strlen(date) + 1)) {
            return;
        }

        HcfX509CertChainBuildParameters inParams = {};
        HcfX509CertChainBuildResult *returnObj = nullptr;
        CfEncodingBlob inStream = { 0 };
        inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testSelfSignedCaCertValid));
        inStream.encodingFormat = CF_FORMAT_PEM;
        inStream.len = strlen(g_testSelfSignedCaCertValid) + 1;
        CfResult ret = BuildX509CertMatchParamsDataNoCRL(&inStream, &inParams.validateParameters);
        if (ret != CF_SUCCESS) {
            return;
        }

        inParams.maxlength = *reinterpret_cast<const int32_t *>(data);
        CfBlob issue;
        issue.data = const_cast<uint8_t *>(data);
        issue.size = size;
        inParams.certMatchParameters.issuer = &issue;
        inParams.certMatchParameters.minPathLenConstraint = -1;

        CfBlob validDate;
        validDate.data = const_cast<uint8_t *>(data);
        validDate.size = strlen(date) + 1;
        inParams.certMatchParameters.issuer = &issue;
    
        ret = HcfCertChainBuildResultCreate(&inParams, &returnObj);
        if (ret != CF_SUCCESS) {
            FreeX509CertMatchParamsData(&inParams.validateParameters);
            return;
        }
        FreeX509CertMatchParamsData(&inParams.validateParameters);
        FreeHcfX509CertChainBuildResult(returnObj);
    }

    static void OneCreateTrustAnchorWithKeyStore()
    {
        CfBlob keyStore;
        CfBlob pwd;
        HcfX509TrustAnchorArray *trustAnchorArray = NULL;

        keyStore.data = const_cast<uint8_t *>(g_testChainKeystore);
        keyStore.size = sizeof(g_testChainKeystore);
        pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testKeystorePwd));
        pwd.size = sizeof(g_testKeystorePwd);
        CfResult result = HcfCreateTrustAnchorWithKeyStore(&keyStore, &pwd, &trustAnchorArray);
        if (result != CF_SUCCESS) {
            return;
        }
        FreeTrustAnchorArr1(*trustAnchorArray);
        CfFree(trustAnchorArray);
        return;
    }

    void X509BuildResultCreateFuzzTest(const uint8_t* data, size_t size)
    {
        if (g_testCreateTrustAnchorFlag) {
            OneCreateTrustAnchorWithKeyStore();
            g_testCreateTrustAnchorFlag = false;
        }
        CfBlob keyStore;
        CfBlob pwd;
        HcfX509TrustAnchorArray *trustAnchorArray = NULL;

        keyStore.data = const_cast<uint8_t *>(data);
        keyStore.size = size;
        pwd.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testKeystorePwd));
        pwd.size = sizeof(g_testKeystorePwd);
        CfResult result = HcfCreateTrustAnchorWithKeyStore(&keyStore, &pwd, &trustAnchorArray);
        if (result != CF_SUCCESS) {
            return;
        }
        FreeTrustAnchorArr1(*trustAnchorArray);
        CfFree(trustAnchorArray);
        return;
    }
    }

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::X509CertChainFuzzTest(data, size, CF_FORMAT_DER);
    OHOS::X509CertChainFuzzTest(data, size, CF_FORMAT_PKCS7);
    OHOS::X509CertChainFuzzTest(data, size, CF_FORMAT_PEM);
    OHOS::X509CertChainValidatorCreateFuzzTest(data, size, CF_FORMAT_DER);
    OHOS::X509CertChainValidatorCreateFuzzTest(data, size, CF_FORMAT_PKCS7);
    OHOS::X509CertChainValidatorCreateFuzzTest(data, size, CF_FORMAT_PEM);
    OHOS::X509BuildResultCreateFuzzTest(data, size, CF_FORMAT_DER);
    OHOS::X509BuildResultCreateFuzzTest(data, size, CF_FORMAT_PKCS7);
    OHOS::X509BuildResultCreateFuzzTest(data, size, CF_FORMAT_PEM);
    OHOS::X509BuildResultCreateFuzzTest(data, size);
    return 0;
}
