/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef ANI_CERT_EXTENSION_H
#define ANI_CERT_EXTENSION_H

#include "ani_common.h"
#include "cf_api.h"

namespace ANI::CertFramework {
class CertExtensionImpl {
public:
    CertExtensionImpl();
    explicit CertExtensionImpl(CfObject *object);
    ~CertExtensionImpl();

    EncodingBlob GetEncoded();
    DataArray GetOidList(ExtensionOidType valueType);
    DataBlob GetEntry(ExtensionEntryType valueType, DataBlob const& oid);
    int32_t CheckCA();
    bool HasUnsupportedCriticalExtension();

private:
    CfObject *object_ = nullptr;
};
} // namespace ANI::CertFramework

#endif // ANI_CERT_EXTENSION_H
