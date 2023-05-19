/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef CF_X509_CRL_ENTRY_H
#define CF_X509_CRL_ENTRY_H

#include "cf_blob.h"
#include "cf_object_base.h"
#include "cf_result.h"

typedef struct HcfX509CrlEntry HcfX509CrlEntry;

struct HcfX509CrlEntry {
    /** HcfX509CrlEntry inherit CfObjectBase. */
    struct CfObjectBase base;

    /** Returns the ASN of this CRL entry 1 der coding form, i.e. internal sequence. */
    CfResult (*getEncoded)(HcfX509CrlEntry *self, CfEncodingBlob *encodedOut);

    /** Get the serial number from this x509crl entry. */
    CfResult (*getSerialNumber)(HcfX509CrlEntry *self, CfBlob *out);

    /** Gets the issuer of the x509 certificate described by this entry. */
    CfResult (*getCertIssuer)(HcfX509CrlEntry *self, CfBlob *encodedOut);

    /** Get the revocation date from x509crl entry. */
    CfResult (*getRevocationDate)(HcfX509CrlEntry *self, CfBlob *out);
};

#endif // CF_X509_CRL_ENTRY_H