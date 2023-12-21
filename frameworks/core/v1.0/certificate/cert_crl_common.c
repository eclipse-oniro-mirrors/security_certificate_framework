/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "cert_crl_common.h"
#include "cf_log.h"
#include "cf_memory.h"

CfResult CloneCertificateObj(HcfX509Certificate *in, HcfX509Certificate **out)
{
    CfEncodingBlob encodingBlob = { 0 };
    CfResult res = in->base.getEncoded(&(in->base), &encodingBlob);
    if (res != CF_SUCCESS) {
        LOGE("Get encoded failed.");
        return res;
    }
    HcfX509Certificate *clone = NULL;
    res = HcfX509CertificateCreate(&encodingBlob, &clone);
    if (res != CF_SUCCESS) {
        LOGE("Failed to HcfX509CertificateCreate!");
        CfFree(encodingBlob.data);
        return res;
    }
    *out = clone;
    CfFree(encodingBlob.data);
    return CF_SUCCESS;
}

CfResult CloneCrlObj(HcfX509Crl *in, HcfX509Crl **out)
{
    CfEncodingBlob encodingBlob = { 0 };
    CfResult res = in->getEncoded(in, &encodingBlob);
    if (res != CF_SUCCESS) {
        LOGE("Failed to getEncoded!");
        return res;
    }
    HcfX509Crl *clone = NULL;
    res = HcfX509CrlCreate(&encodingBlob, &clone);
    if (res != CF_SUCCESS) {
        LOGE("Failed to HcfX509CrlCreate!");
        CfFree(encodingBlob.data);
        return res;
    }
    *out = clone;
    CfFree(encodingBlob.data);
    return CF_SUCCESS;
}

void FreeCertArrayData(HcfX509CertificateArray *certs)
{
    if (certs == NULL) {
        return;
    }
    for (uint32_t i = 0; i < certs->count; ++i) {
        CfObjDestroy(certs->data[i]);
    }
    CF_FREE_PTR(certs->data);
    certs->count = 0;
}

void FreeCrlArrayData(HcfX509CrlArray *crls)
{
    if (crls == NULL) {
        return;
    }
    for (uint32_t i = 0; i < crls->count; ++i) {
        CfObjDestroy(crls->data[i]);
    }
    CF_FREE_PTR(crls->data);
    crls->count = 0;
}
