/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#ifndef CF_CERT_CHAIN_VALIDATOR_SPI_H
#define CF_CERT_CHAIN_VALIDATOR_SPI_H

#include "cf_blob.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "x509_certificate.h"
#include "x509_cert_chain_validate_params.h"
#include "x509_cert_chain_validate_result.h"
#include "cert_chain_validator.h"

typedef struct HcfCertChainValidatorSpi HcfCertChainValidatorSpi;

struct HcfCertChainValidatorSpi {
    CfObjectBase base;
    CfResult (*engineValidate)(HcfCertChainValidatorSpi *self, const CfArray *certsList);
    CfResult (*engineValidateX509Cert)(HcfCertChainValidatorSpi *self, HcfX509Certificate *cert,
        const HcfX509CertValidatorParams *params, HcfCertVerifyResult *result);
};

#endif // CF_CERT_CHAIN_VALIDATOR_SPI_H
