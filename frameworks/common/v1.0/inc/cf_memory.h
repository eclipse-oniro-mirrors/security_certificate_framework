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

#ifndef CF_MEMORY_H
#define CF_MEMORY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void *CfMalloc(uint32_t size, char val);
void CfFree(void* addr);

#define MAX_MEMORY_SIZE (5 * 1024 * 1024)

#define SELF_FREE_PTR(PTR, FREE_FUNC) \
{ \
    if ((PTR) != NULL) { \
        FREE_FUNC(PTR); \
        (PTR) = NULL; \
    } \
}

#define CF_FREE_PTR(p) SELF_FREE_PTR(p, CfFree)

#define CF_FREE_BLOB(blob) do { \
    if ((blob).data != NULL) { \
        CfFree((blob).data); \
        (blob).data = NULL; \
    } \
    (blob).size = 0; \
} while (0)

#ifdef __cplusplus
}
#endif

#endif
