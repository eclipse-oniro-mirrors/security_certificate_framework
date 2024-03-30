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

#ifndef CF_X509_CRL_SPI_H
#define CF_X509_CRL_SPI_H

#include "cf_blob.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "pub_key.h"
#include "x509_certificate.h"
#include "x509_crl_entry.h"
#include "x509_crl_match_parameters.h"
#include "x509_distinguished_name.h"

typedef struct HcfX509CrlSpi HcfX509CrlSpi;

struct HcfX509CrlSpi {
    CfObjectBase base;

    const char *(*engineGetType)(HcfX509CrlSpi *self);

    bool (*engineIsRevoked)(HcfX509CrlSpi *self, const HcfCertificate *cert);

    CfResult (*engineGetEncoded)(HcfX509CrlSpi *self, CfEncodingBlob *encodedByte);

    CfResult (*engineVerify)(HcfX509CrlSpi *self, HcfPubKey *key);

    long (*engineGetVersion)(HcfX509CrlSpi *self);

    CfResult (*engineGetIssuerName)(HcfX509CrlSpi *self, CfBlob *out);

    CfResult (*engineGetLastUpdate)(HcfX509CrlSpi *self, CfBlob *out);

    CfResult (*engineGetNextUpdate)(HcfX509CrlSpi *self, CfBlob *out);

    CfResult (*engineGetRevokedCert)(HcfX509CrlSpi *self, const CfBlob *serialNumber, HcfX509CrlEntry **entryOut);

    CfResult (*engineGetRevokedCertWithCert)(HcfX509CrlSpi *self, HcfX509Certificate *cert,
        HcfX509CrlEntry **entryOut);

    CfResult (*engineGetRevokedCerts)(HcfX509CrlSpi *self, CfArray *entrysOut);

    CfResult (*engineGetTbsInfo)(HcfX509CrlSpi *self, CfBlob *tbsCertListOut);

    CfResult (*engineGetSignature)(HcfX509CrlSpi *self, CfBlob *signature);

    CfResult (*engineGetSignatureAlgName)(HcfX509CrlSpi *self, CfBlob *out);

    CfResult (*engineGetSignatureAlgOid)(HcfX509CrlSpi *self, CfBlob *out);

    CfResult (*engineGetSignatureAlgParams)(HcfX509CrlSpi *self, CfBlob *sigAlgParamOut);

    CfResult (*engineGetExtensions)(HcfX509CrlSpi *self, CfBlob *out);

    CfResult (*engineMatch)(HcfX509CrlSpi *self, const HcfX509CrlMatchParams *matchParams, bool *out);

    CfResult (*engineToString)(HcfX509CrlSpi *self, CfBlob *out);

    CfResult (*engineHashCode)(HcfX509CrlSpi *self, CfBlob *out);

    CfResult (*engineGetExtensionsObject)(HcfX509CrlSpi *self, CfBlob *out);
};

#endif // CF_X509_CRL_SPI_H
