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

#ifndef HCF_CONFIG_H
#define HCF_CONFIG_H

#define HCF_MAX_STR_LEN 1024 // input string parameter max length limit, include \0
#define HCF_MAX_ALGO_NAME_LEN 128 // input algoName parameter max length limit, include \0
#define LOG_PRINT_MAX_LEN 1024 // log max length limit
#define HCF_MAX_BUFFER_LEN 8192
#define SERIAL_NUMBER_HEDER_SIZE 2
#define MAX_SN_BYTE_CNT 24 // the maximum number of bytes of the serial number
#define INVALID_VERSION (-1)
#define INVALID_CONSTRAINTS_LEN (-1)
#define CF_MAX_URI_COUNT 100

#endif
