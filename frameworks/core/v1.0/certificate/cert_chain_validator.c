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

#include "cert_chain_validator.h"

#include <securec.h>

#include "cf_blob.h"
#include "cert_chain_validator_spi.h"
#include "config.h"
#include "cf_result.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "utils.h"
#include "x509_cert_chain_validator_openssl.h"

#define LV_LENGTH_LEN sizeof(uint16_t)
#define MAX_CERT_PATH_DATA_LEM 8192

typedef CfResult (*CertChainValidatorSpiCreateFunc)(HcfCertChainValidatorSpi **);

typedef struct {
    HcfCertChainValidator base;
    HcfCertChainValidatorSpi *spiObj;
    char *algorithm;
} CertChainValidatorImpl;

typedef struct {
    CertChainValidatorSpiCreateFunc createFunc;
} HcfCertChainValidatorFuncSet;

typedef struct {
    const char *algorithm;
    HcfCertChainValidatorFuncSet funcSet;
} HcfCertChainValidatorAbility;

static const HcfCertChainValidatorAbility CERT_PATH_VALIDATOR_ABILITY_SET[] = {
    { "PKIX", { HcfCertChainValidatorSpiCreate } }
};

static const HcfCertChainValidatorFuncSet *FindAbility(const char *algorithm)
{
    for (uint32_t i = 0; i < sizeof(CERT_PATH_VALIDATOR_ABILITY_SET) / sizeof(HcfCertChainValidatorAbility); i++) {
        if (strcmp(CERT_PATH_VALIDATOR_ABILITY_SET[i].algorithm, algorithm) == 0) {
            return &(CERT_PATH_VALIDATOR_ABILITY_SET[i].funcSet);
        }
    }
    LOGE("Algorithm for certChain validator is not support! [algorithm]: %s", algorithm);
    return NULL;
}

static const char *GetCertChainValidatorClass(void)
{
    return "HcfCertChainValidator";
}

static void DestroyCertChainValidator(CfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return;
    }
    if (!IsClassMatch(self, GetCertChainValidatorClass())) {
        LOGE("Class is not match.");
        return;
    }
    CertChainValidatorImpl *validatorImpl = (CertChainValidatorImpl *)self;
    CfObjDestroy(validatorImpl->spiObj);
    CfFree(validatorImpl->algorithm);
    validatorImpl->algorithm = NULL;
    CfFree(validatorImpl);
}

static CfResult ConvertCertBuffer2List(const HcfCertChainData *certChainData, CfArray *certsList)
{
    uint8_t *msg = certChainData->data;
    const uint8_t *boundary = certChainData->data + certChainData->dataLen;
    uint32_t index = 0;
    CfResult res = CF_SUCCESS;
    while (msg < boundary) {
        if (index >= certsList->count || (msg + LV_LENGTH_LEN > boundary)) {
            LOGE("Invalid index for l-v len!");
            res = CF_INVALID_PARAMS;
            break;
        }
        uint16_t entryLen = 0;
        if (memcpy_s(&entryLen, LV_LENGTH_LEN, msg, LV_LENGTH_LEN) != EOK) {
            LOGE("Input data in too long.");
            return CF_ERR_COPY;
        }
        msg = msg + LV_LENGTH_LEN;
        certsList->data[index].data = (uint8_t *)CfMalloc(entryLen, 0);
        if (certsList->data[index].data == NULL) {
            LOGE("Failed to malloc data for cert, index = %u.", index);
            res = CF_ERR_MALLOC;
            break;
        }
        if (msg + entryLen > boundary) {
            LOGE("Entry len is overflow for boundary!");
            res = CF_INVALID_PARAMS;
            break;
        }
        if (memcpy_s(certsList->data[index].data, entryLen, msg, entryLen) != EOK) {
            res = CF_ERR_COPY;
            break;
        }
        certsList->data[index].size = entryLen;
        msg = msg + entryLen;
        index++;
    }
    return res;
}

static CfResult Validate(HcfCertChainValidator *self, const HcfCertChainData *certChainData)
{
    if ((self == NULL) || (certChainData == NULL) || (certChainData->dataLen > MAX_CERT_PATH_DATA_LEM)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetCertChainValidatorClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    CertChainValidatorImpl *impl = (CertChainValidatorImpl *)self;
    CfArray certsList = { NULL, 0 };
    certsList.format = certChainData->format;
    certsList.count = certChainData->count;
    uint32_t certsLen = sizeof(CfBlob) * certsList.count;
    certsList.data = (CfBlob *)CfMalloc(certsLen, 0);
    if (certsList.data == NULL) {
        LOGE("Failed to new memory for certs.");
        return CF_ERR_MALLOC;
    }
    CfResult res = ConvertCertBuffer2List(certChainData, &certsList);
    if (res != CF_SUCCESS) {
        LOGE("Failed to convert buffer to lists.");
        CfArrayDataClearAndFree(&certsList);
        return res;
    }
    res = impl->spiObj->engineValidate(impl->spiObj, &certsList);
    CfArrayDataClearAndFree(&certsList);
    return res;
}

static const char *GetAlgorithm(HcfCertChainValidator *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetCertChainValidatorClass())) {
        LOGE("Class is not match.");
        return NULL;
    }
    CertChainValidatorImpl *impl = (CertChainValidatorImpl *)self;
    const char *algo = (const char *)impl->algorithm;
    return algo;
}

CfResult HcfCertChainValidatorCreate(const char *algorithm, HcfCertChainValidator **pathValidator)
{
    CF_LOG_I("enter");
    if (!IsStrValid(algorithm, HCF_MAX_STR_LEN) || (pathValidator == NULL)) {
        return CF_INVALID_PARAMS;
    }
    const HcfCertChainValidatorFuncSet *func = FindAbility(algorithm);
    if (func == NULL) {
        LOGE("Func is null!");
        return CF_NOT_SUPPORT;
    }

    HcfCertChainValidatorSpi *spiObj = NULL;
    CfResult res = func->createFunc(&spiObj);
    if (res != CF_SUCCESS) {
        LOGE("Failed to create certChain validator spi object!");
        return res;
    }
    CertChainValidatorImpl *returnValidator = (CertChainValidatorImpl *)CfMalloc(sizeof(CertChainValidatorImpl), 0);
    if (returnValidator == NULL) {
        LOGE("Failed to allocate returnValidator memory!");
        CfObjDestroy(spiObj);
        return CF_ERR_MALLOC;
    }
    returnValidator->base.validate = Validate;
    returnValidator->base.getAlgorithm = GetAlgorithm;
    returnValidator->base.base.destroy = DestroyCertChainValidator;
    returnValidator->base.base.getClass = GetCertChainValidatorClass;
    returnValidator->spiObj = spiObj;
    uint32_t algoNameLen = strlen(algorithm) + 1;
    returnValidator->algorithm = (char *)CfMalloc(algoNameLen, 0);
    if (returnValidator->algorithm == NULL) {
        LOGE("Failed to allocate algorithm memory!");
        CfFree(returnValidator);
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(returnValidator->algorithm, algoNameLen, algorithm, algoNameLen);

    *pathValidator = (HcfCertChainValidator *)returnValidator;
    return CF_SUCCESS;
}