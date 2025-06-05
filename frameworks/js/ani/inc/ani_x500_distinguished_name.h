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

#ifndef ANI_X509_DISTINGUISHED_NAME_H
#define ANI_X509_DISTINGUISHED_NAME_H

#include "ani_common.h"

namespace ANI::CertFramework {
class X500DistinguishedNameImpl {
public:
    X500DistinguishedNameImpl();
    ~X500DistinguishedNameImpl();

    string GetName();
    string GetNameByEnum(EncodingType encodingType);
    array<string> GetNameByStr(string_view type);
    EncodingBlob GetEncoded();
};
} // namespace ANI::CertFramework


#endif // ANI_X509_DISTINGUISHED_NAME_H