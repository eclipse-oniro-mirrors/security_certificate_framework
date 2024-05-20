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

#include "cert_crl_collection.h"

#include <securec.h>

#include "cf_blob.h"
#include "config.h"
#include "cf_result.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "utils.h"
#include "x509_certificate.h"
#include "x509_crl.h"
#include "cert_crl_common.h"

typedef struct {
    HcfCertCrlCollection base;
    HcfX509CertificateArray certs;
    HcfX509CrlArray crls;
} CertCrlCollectionImpl;

static const char *GetCertCrlCollectionClass(void)
{
    return "HcfCertCrlCollection";
}

static void DestroyCertCrlCollection(CfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return;
    }
    if (!IsClassMatch(self, GetCertCrlCollectionClass())) {
        LOGE("Class is not match.");
        return;
    }

    CertCrlCollectionImpl *collectionImpl = (CertCrlCollectionImpl *)self;
    FreeCertArrayData(&collectionImpl->certs);
    FreeCrlArrayData(&collectionImpl->crls);
    CfFree(collectionImpl);
}

static CfResult GetMatchCerts(const HcfX509CertificateArray *inCerts, const HcfX509CertMatchParams *matchParams,
    HcfX509CertificateArray *outCerts)
{
    HcfX509CertificateArray tmpArr = { NULL, 0 };
    tmpArr.count = inCerts->count;
    /* inCerts is inner object, the size has been checked in function HcfCertCrlCollectionCreate */
    tmpArr.data = (HcfX509Certificate **)CfMalloc(inCerts->count * sizeof(HcfX509Certificate *), 0);
    if (tmpArr.data == NULL) {
        LOGE("Failed to allocate memory!");
        return CF_ERR_MALLOC;
    }
    uint32_t outInd = 0;
    for (uint32_t i = 0; i < inCerts->count; ++i) {
        HcfX509Certificate *cert = inCerts->data[i];
        bool out = false;
        CfResult res = cert->match(cert, matchParams, &out);
        if (res != CF_SUCCESS) {
            LOGE("match failed");
            FreeCertArrayData(&tmpArr);
            return res;
        }
        if (!out) {
            continue;
        }
        res = CloneCertificateObj(cert, &(tmpArr.data[outInd]));
        if (res != CF_SUCCESS) {
            LOGE("cert clone failed");
            FreeCertArrayData(&tmpArr);
            return res;
        }
        outInd++;
    }
    if (outInd == 0) {
        LOGI("no any match!");
        FreeCertArrayData(&tmpArr);
        return CF_SUCCESS;
    }
    outCerts->data = (HcfX509Certificate **)CfMalloc(outInd * sizeof(HcfX509Certificate *), 0);
    if (outCerts->data == NULL) {
        LOGE("Failed to allocate memory!");
        FreeCertArrayData(&tmpArr);
        return CF_ERR_MALLOC;
    }
    outCerts->count = outInd;
    for (uint32_t i = 0; i < outInd; ++i) {
        outCerts->data[i] = tmpArr.data[i];
    }
    CfFree(tmpArr.data);
    return CF_SUCCESS;
}

static CfResult GetMatchCRLs(
    const HcfX509CrlArray *inCrls, const HcfX509CrlMatchParams *matchParams, HcfX509CrlArray *outCrls)
{
    HcfX509CrlArray tmpArr = { NULL, 0 };
    tmpArr.count = inCrls->count;
    /* inCrls is inner object, the size has been checked in function HcfCertCrlCollectionCreate */
    tmpArr.data = (HcfX509Crl **)CfMalloc(inCrls->count * sizeof(HcfX509Crl *), 0);
    if (tmpArr.data == NULL) {
        LOGE("Failed to allocate memory!");
        return CF_ERR_MALLOC;
    }
    uint32_t outInd = 0;
    for (uint32_t i = 0; i < inCrls->count; ++i) {
        HcfX509Crl *crl = inCrls->data[i];
        bool out = false;
        CfResult res = crl->match(crl, matchParams, &out);
        if (res != CF_SUCCESS) {
            LOGE("match failed");
            FreeCrlArrayData(&tmpArr);
            return res;
        }
        if (!out) {
            continue;
        }
        res = CloneCrlObj(crl, &tmpArr.data[outInd]);
        if (res != CF_SUCCESS) {
            LOGE("crl clone failed");
            FreeCrlArrayData(&tmpArr);
            return res;
        }
        outInd++;
    }
    if (outInd == 0) {
        LOGI("no any match!");
        FreeCrlArrayData(&tmpArr);
        return CF_SUCCESS;
    }
    outCrls->data = (HcfX509Crl **)CfMalloc(outInd * sizeof(HcfX509Crl *), 0);
    if (outCrls->data == NULL) {
        LOGE("Failed to allocate memory!");
        FreeCrlArrayData(&tmpArr);
        return CF_ERR_MALLOC;
    }
    outCrls->count = outInd;
    for (uint32_t i = 0; i < outInd; ++i) {
        outCrls->data[i] = tmpArr.data[i];
    }
    CfFree(tmpArr.data);
    return CF_SUCCESS;
}

static CfResult SelectCerts(
    HcfCertCrlCollection *self, const HcfX509CertMatchParams *matchParams, HcfX509CertificateArray *retCerts)
{
    if (self == NULL || matchParams == NULL || retCerts == NULL) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetCertCrlCollectionClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    CertCrlCollectionImpl *collectionImpl = (CertCrlCollectionImpl *)self;
    if (collectionImpl->certs.count == 0) {
        LOGE("no any certs for select.");
        return CF_INVALID_PARAMS;
    }
    CfResult res = GetMatchCerts(&collectionImpl->certs, matchParams, retCerts);
    if (res != CF_SUCCESS) {
        LOGE("match failed");
        return res;
    }
    return CF_SUCCESS;
}

static CfResult SelectCRLs(
    HcfCertCrlCollection *self, const HcfX509CrlMatchParams *matchParams, HcfX509CrlArray *retCrls)
{
    if (self == NULL || matchParams == NULL || retCrls == NULL) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetCertCrlCollectionClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    CertCrlCollectionImpl *collectionImpl = (CertCrlCollectionImpl *)self;
    if (collectionImpl->crls.count == 0) {
        LOGE("no any crls for select.");
        return CF_INVALID_PARAMS;
    }
    CfResult res = GetMatchCRLs(&collectionImpl->crls, matchParams, retCrls);
    if (res != CF_SUCCESS) {
        LOGE("match failed");
        return res;
    }
    return CF_SUCCESS;
}

static CfResult GetCRLs(HcfCertCrlCollection *self, HcfX509CrlArray **retCrls)
{
    if (self == NULL || retCrls == NULL) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetCertCrlCollectionClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    CertCrlCollectionImpl *collectionImpl = (CertCrlCollectionImpl *)self;
    *retCrls = &(collectionImpl->crls);

    return CF_SUCCESS;
}

static CfResult CloneCertArray(const HcfX509CertificateArray *inCerts, HcfX509CertificateArray *certs)
{
    if (inCerts == NULL || inCerts->count == 0) {
        LOGI("inCerts is null, or count is 0.");
        return CF_SUCCESS;
    }

    if (inCerts->count > MAX_LEN_OF_CERT_CRL_ARR || certs == NULL) {
        LOGE("array count is over limit.");
        return CF_INVALID_PARAMS;
    }

    certs->data = (HcfX509Certificate **)CfMalloc(inCerts->count * sizeof(HcfX509Certificate *), 0);
    if (certs->data == NULL) {
        LOGE("Failed to allocate memory!");
        return CF_ERR_MALLOC;
    }
    certs->count = inCerts->count;
    CfResult res = CF_SUCCESS;
    for (uint32_t i = 0; i < inCerts->count; ++i) {
        res = CloneCertificateObj(inCerts->data[i], &(certs->data[i]));
        if (res != CF_SUCCESS) {
            break;
        }
    }
    if (res != CF_SUCCESS) {
        FreeCertArrayData(certs);
        LOGE("Failed to clone cert!");
        return res;
    }
    return CF_SUCCESS;
}

static CfResult CloneCrlArray(const HcfX509CrlArray *inCrls, HcfX509CrlArray *crls)
{
    if (inCrls == NULL || inCrls->count == 0) {
        LOGI("inCrls is null, or count is 0.");
        return CF_SUCCESS;
    }

    if (inCrls->count > MAX_LEN_OF_CERT_CRL_ARR || crls == NULL) {
        LOGE("array count is over limit.");
        return CF_INVALID_PARAMS;
    }

    crls->data = (HcfX509Crl **)CfMalloc(inCrls->count * sizeof(HcfX509Crl *), 0);
    if (crls->data == NULL) {
        LOGE("Failed to allocate memory!");
        return CF_ERR_MALLOC;
    }

    crls->count = inCrls->count;
    CfResult res = CF_SUCCESS;
    for (uint32_t i = 0; i < inCrls->count; ++i) {
        res = CloneCrlObj(inCrls->data[i], &(crls->data[i]));
        if (res != CF_SUCCESS) {
            break;
        }
    }
    if (res != CF_SUCCESS) {
        FreeCrlArrayData(crls);
        LOGE("Failed to clone crl!");
        return res;
    }
    return CF_SUCCESS;
}

CfResult HcfCertCrlCollectionCreate(
    const HcfX509CertificateArray *inCerts, const HcfX509CrlArray *inCrls, HcfCertCrlCollection **out)
{
    CF_LOG_I("enter");
    if (out == NULL) {
        LOGE("input params invalid!");
        return CF_INVALID_PARAMS;
    }

    CertCrlCollectionImpl *ret = (CertCrlCollectionImpl *)CfMalloc(sizeof(CertCrlCollectionImpl), 0);
    if (ret == NULL) {
        LOGE("Failed to allocate ret memory!");
        return CF_ERR_MALLOC;
    }

    ret->base.base.destroy = DestroyCertCrlCollection;
    ret->base.base.getClass = GetCertCrlCollectionClass;
    ret->base.selectCerts = SelectCerts;
    ret->base.selectCRLs = SelectCRLs;
    ret->base.getCRLs = GetCRLs;

    CfResult res = CloneCertArray(inCerts, &(ret->certs));
    if (res != CF_SUCCESS) {
        LOGE("Failed to clone cert array!");
        CfFree(ret);
        return res;
    }
    res = CloneCrlArray(inCrls, &(ret->crls));
    if (res != CF_SUCCESS) {
        LOGE("Failed to clone crl array!");
        FreeCertArrayData(&ret->certs);
        CfFree(ret);
        return res;
    }

    *out = (HcfCertCrlCollection *)ret;
    return CF_SUCCESS;
}
