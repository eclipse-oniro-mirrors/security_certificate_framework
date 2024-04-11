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

#ifndef CF_X509_CERT_CHAIN_SPI_H
#define CF_X509_CERT_CHAIN_SPI_H

#include "cf_blob.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "x509_cert_chain_validate_params.h"
#include "x509_cert_chain_validate_result.h"
#include "x509_certificate.h"

typedef struct HcfX509CertChainSpi HcfX509CertChainSpi;

struct HcfX509CertChainSpi {
    CfObjectBase base;
    CfResult (*engineGetCertList)(HcfX509CertChainSpi *self, HcfX509CertificateArray *out);
    CfResult (*engineValidate)(HcfX509CertChainSpi *self, const HcfX509CertChainValidateParams *params,
        HcfX509CertChainValidateResult *result);
    CfResult (*engineToString)(HcfX509CertChainSpi *self, CfBlob *out);
    CfResult (*engineHashCode)(HcfX509CertChainSpi *self, CfBlob *out);
};

#endif // CF_X509_CERT_CHAIN_SPI_H
