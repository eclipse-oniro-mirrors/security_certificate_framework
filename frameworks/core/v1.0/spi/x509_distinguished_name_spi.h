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

#ifndef CF_X509_DISTINGUISHED_NAME_SPI_H
#define CF_X509_DISTINGUISHED_NAME_SPI_H

#include "cf_blob.h"
#include "cf_object_base.h"
#include "cf_result.h"

typedef struct HcfX509DistinguishedNameSpi HcfX509DistinguishedNameSpi;

struct HcfX509DistinguishedNameSpi {
    CfObjectBase base;

    CfResult (*engineGetEncode)(HcfX509DistinguishedNameSpi *self, CfEncodingBlob *out);

    CfResult (*engineGetName)(HcfX509DistinguishedNameSpi *self, CfBlob *type, CfBlob *out, CfArray *outArr);
};

#endif // CF_X509_DISTINGUISHED_NAME_SPI_H
