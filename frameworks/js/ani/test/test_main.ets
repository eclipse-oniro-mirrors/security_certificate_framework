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

import utils from "./test_utils";
import { testX509Cert } from "./test_x509_cert";
import { testCertChainValidator } from "./test_cert_chain_validator";
import { testX509Crl } from "./test_x509_crl";
import { testX509CrlEntry } from "./test_x509_crl_entry";
import { testCertCrlCollection } from "./test_cert_crl_collection";

function main() {
  testX509Cert();
  testCertChainValidator();
  testX509Crl();
  testX509CrlEntry();
  testCertCrlCollection();

  utils.doFullGC();
  utils.stopTaskPool();
}
