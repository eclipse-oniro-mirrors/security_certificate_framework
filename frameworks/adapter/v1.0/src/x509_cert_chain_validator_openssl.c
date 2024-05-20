/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "x509_cert_chain_validator_openssl.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "cf_blob.h"
#include "config.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "utils.h"
#include "cf_result.h"
#include "certificate_openssl_common.h"

#define X509_CERT_CHAIN_VALIDATOR_OPENSSL_CLASS "X509CertChainValidatorOpensslClass"

typedef struct {
    uint8_t *data;
    size_t len;
    X509 *x509;
} CertsInfo;

typedef struct {
    int32_t errCode;
    CfResult result;
} OpensslErrorToResult;

static const OpensslErrorToResult ERROR_TO_RESULT_MAP[] = {
    { X509_V_OK, CF_SUCCESS },
    { X509_V_ERR_CERT_SIGNATURE_FAILURE, CF_ERR_CERT_SIGNATURE_FAILURE },
    { X509_V_ERR_CERT_NOT_YET_VALID, CF_ERR_CERT_NOT_YET_VALID },
    { X509_V_ERR_CERT_HAS_EXPIRED, CF_ERR_CERT_HAS_EXPIRED },
    { X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
    { X509_V_ERR_KEYUSAGE_NO_CERTSIGN, CF_ERR_KEYUSAGE_NO_CERTSIGN },
    { X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE, CF_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE },
};

static CfResult ConvertOpensslErrorMsg(int32_t errCode)
{
    for (uint32_t i = 0; i < sizeof(ERROR_TO_RESULT_MAP) / sizeof(OpensslErrorToResult); i++) {
        if (ERROR_TO_RESULT_MAP[i].errCode == errCode) {
            return ERROR_TO_RESULT_MAP[i].result;
        }
    }
    return CF_ERR_CRYPTO_OPERATION;
}

static const char *GetX509CertChainValidatorClass(void)
{
    return X509_CERT_CHAIN_VALIDATOR_OPENSSL_CLASS;
}

static void DestroyX509CertChainValidator(CfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Invalid params!");
        return;
    }
    if (!IsClassMatch(self, GetX509CertChainValidatorClass())) {
        LOGE("Class is not match.");
        return;
    }
    CfFree((HcfCertChainValidatorSpi *)self);
}

static CfResult InitX509Certs(const CfArray *certsList, CertsInfo **certs)
{
    uint32_t certsInfoLen = sizeof(CertsInfo) * certsList->count;
    CertsInfo *certsInfo = (CertsInfo *)CfMalloc(certsInfoLen, 0);
    if (certsInfo == NULL) {
        LOGE("Failed to new memory for cert info.");
        return CF_ERR_MALLOC;
    }
    for (uint32_t i = 0; i < certsList->count; ++i) {
        CertsInfo *info = &(certsInfo[i]);
        info->data = certsList->data[i].data;
        info->len = certsList->data[i].size;
    }
    *certs = certsInfo;
    return CF_SUCCESS;
}

static void FreeX509Certs(CertsInfo **certs, uint32_t certNum)
{
    if (certs == NULL) {
        LOGD("Input NULL certs, no need to free.");
        return;
    }
    for (uint32_t i = 0; i < certNum; ++i) {
        if ((*certs)[i].x509 != NULL) {
            X509_free((*certs)[i].x509);
            (*certs)[i].x509 = NULL;
        }
    }
    CfFree(*certs);
    *certs = NULL;
}

static X509 *GetX509Cert(const uint8_t *data, size_t len, enum CfEncodingFormat format)
{
    X509 *x509 = NULL;
    BIO *bio = BIO_new_mem_buf(data, len);
    if (bio == NULL) {
        LOGE("Failed to new memory for bio.");
        return NULL;
    }

    if (format == CF_FORMAT_DER) {
        x509 = d2i_X509_bio(bio, NULL);
    } else if (format == CF_FORMAT_PEM) {
        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    }

    BIO_free(bio);
    return x509;
}

static CfResult ValidateCertChainInner(CertsInfo *certs, uint32_t certNum)
{
    CfResult res = CF_SUCCESS;
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *verifyCtx = X509_STORE_CTX_new();
    do {
        if ((store == NULL) || (verifyCtx == NULL)) {
            LOGE("Failed to verify cert chain init.");
            res = CF_ERR_MALLOC;
            break;
        }

        for (uint32_t i = certNum - 1; i > 0; i--) { // certs[certNum - 1] represents the 0th cert.
            if (X509_STORE_add_cert(store, certs[i].x509) != CF_OPENSSL_SUCCESS) {
                LOGE("Failed to add cert to store.");
                CfPrintOpensslError();
                res = CF_ERR_MALLOC;
                break;
            }
        }
        if (res != CF_SUCCESS) {
            break;
        }
        /* Do not check cert validity against current time. */
        X509_STORE_set_flags(store, X509_V_FLAG_NO_CHECK_TIME);
        int32_t resOpenssl = X509_STORE_CTX_init(verifyCtx, store, certs[0].x509, NULL);
        if (resOpenssl != CF_OPENSSL_SUCCESS) {
            LOGE("Failed to init verify ctx.");
            res = CF_ERR_CRYPTO_OPERATION;
            CfPrintOpensslError();
            break;
        }
        resOpenssl = X509_verify_cert(verifyCtx);
        if (resOpenssl != CF_OPENSSL_SUCCESS) {
            int32_t errCode = X509_STORE_CTX_get_error(verifyCtx);
            const char *pChError = X509_verify_cert_error_string(errCode);
            LOGE("Failed to verify cert, openssl openssl error code = %d, error msg:%s.", errCode, pChError);
            res = ConvertOpensslErrorMsg(errCode);
            break;
        }
    } while (0);

    if (verifyCtx != NULL) {
        X509_STORE_CTX_free(verifyCtx);
    }
    if (store != NULL) {
        X509_STORE_free(store);
    }
    return res;
}

static CfResult ValidateCertChain(CertsInfo *certs, uint32_t certNum, enum CfEncodingFormat format)
{
    for (uint32_t i = 0; i < certNum; ++i) {
        X509 *x509 = GetX509Cert(certs[i].data, certs[i].len, format);
        if (x509 == NULL) {
            LOGE("Failed to convert cert blob to x509.");
            return CF_ERR_CRYPTO_OPERATION; /* X509 will be freed by caller func. */
        }
        certs[i].x509 = x509;
    }
    return ValidateCertChainInner(certs, certNum);
}

static CfResult Validate(HcfCertChainValidatorSpi *self, const CfArray *certsList)
{
    if ((self == NULL) || (certsList == NULL) || (certsList->count <= 1)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertChainValidatorClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    CertsInfo *certs = NULL;
    CfResult res = InitX509Certs(certsList, &certs);
    if (res != CF_SUCCESS) {
        LOGE("Failed to init certs, res = %d.", res);
        return res;
    }
    res = ValidateCertChain(certs, certsList->count, certsList->format);
    if (res != CF_SUCCESS) {
        LOGE("Failed to validate cert chain, res = %d.", res);
    }
    FreeX509Certs(&certs, certsList->count);
    return res;
}

CfResult HcfCertChainValidatorSpiCreate(HcfCertChainValidatorSpi **spi)
{
    if (spi == NULL) {
        LOGE("Invalid params, spi is null!");
        return CF_INVALID_PARAMS;
    }
    HcfCertChainValidatorSpi *validator = (HcfCertChainValidatorSpi *)CfMalloc(sizeof(HcfCertChainValidatorSpi), 0);
    if (validator == NULL) {
        LOGE("Failed to allocate certChain validator spi object memory!");
        return CF_ERR_MALLOC;
    }
    validator->base.getClass = GetX509CertChainValidatorClass;
    validator->base.destroy = DestroyX509CertChainValidator;
    validator->engineValidate = Validate;

    *spi = validator;
    return CF_SUCCESS;
}