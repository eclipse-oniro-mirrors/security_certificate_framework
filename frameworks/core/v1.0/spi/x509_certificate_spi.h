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

#ifndef CF_X509_CERTIFICATE_SPI_H
#define CF_X509_CERTIFICATE_SPI_H

#include "cf_blob.h"
#include "cf_object_base.h"
#include "pub_key.h"
#include "cf_result.h"
#include "x509_cert_match_parameters.h"

typedef struct HcfX509CertificateSpi HcfX509CertificateSpi;

struct HcfX509CertificateSpi {
    CfObjectBase base;

    CfResult (*engineVerify)(HcfX509CertificateSpi *self, HcfPubKey *key);

    CfResult (*engineGetEncoded)(HcfX509CertificateSpi *self, CfEncodingBlob *encodedByte);

    CfResult (*engineGetPublicKey)(HcfX509CertificateSpi *self, HcfPubKey **keyOut);

    CfResult (*engineCheckValidityWithDate)(HcfX509CertificateSpi *self, const char *date);

    long (*engineGetVersion)(HcfX509CertificateSpi *self);

    CfResult (*engineGetSerialNumber)(HcfX509CertificateSpi *self, CfBlob *out);

    CfResult (*engineGetIssuerName)(HcfX509CertificateSpi *self, CfBlob *out);

    CfResult (*engineGetSubjectName)(HcfX509CertificateSpi *self, CfBlob *out);

    CfResult (*engineGetNotBeforeTime)(HcfX509CertificateSpi *self, CfBlob *outDate);

    CfResult (*engineGetNotAfterTime)(HcfX509CertificateSpi *self, CfBlob *outDate);

    CfResult (*engineGetSignature)(HcfX509CertificateSpi *self, CfBlob *sigOut);

    CfResult (*engineGetSignatureAlgName)(HcfX509CertificateSpi *self, CfBlob *outName);

    CfResult (*engineGetSignatureAlgOid)(HcfX509CertificateSpi *self, CfBlob *out);

    CfResult (*engineGetSignatureAlgParams)(HcfX509CertificateSpi *self, CfBlob *sigAlgParamsOut);

    CfResult (*engineGetKeyUsage)(HcfX509CertificateSpi *self, CfBlob *boolArr);

    CfResult (*engineGetExtKeyUsage)(HcfX509CertificateSpi *self, CfArray *keyUsageOut);

    int32_t (*engineGetBasicConstraints)(HcfX509CertificateSpi *self);

    CfResult (*engineGetSubjectAltNames)(HcfX509CertificateSpi *self, CfArray *outName);

    CfResult (*engineGetIssuerAltNames)(HcfX509CertificateSpi *self, CfArray *outName);

    CfResult (*engineMatch)(HcfX509CertificateSpi *self, const HcfX509CertMatchParams *matchParams, bool *out);

    CfResult (*engineToString)(HcfX509CertificateSpi *self, CfBlob *out);

    CfResult (*engineHashCode)(HcfX509CertificateSpi *self, CfBlob *out);

    CfResult (*engineGetExtensionsObject)(HcfX509CertificateSpi *self, CfBlob *out);

    CfResult (*engineGetCRLDistributionPointsURI)(HcfX509CertificateSpi *self, CfArray *outURI);
};

#endif // CF_X509_CERTIFICATE_SPI_H
