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

#include "cf_memory.h"
#include "memory_mock.h"

#include "cf_log.h"
#include "securec.h"

static bool g_isMock = false;
static uint32_t g_mallocMockIndex = __INT32_MAX__;
static uint32_t g_mallocNum = 0;
static bool g_isRecordMallocNum = false;

void SetMockFlag(bool flag)
{
    g_isMock = flag;
}

void *CfMalloc(uint32_t size, char val)
{
    if (g_isMock) {
        return NULL;
    }
    if (g_isRecordMallocNum) {
        if (g_mallocNum == g_mallocMockIndex) {
            LOGI("mock malloc return NULL.");
            return NULL;
        }
        g_mallocNum++;
    }
    void *addr = malloc(size);
    if (addr != NULL) {
        (void)memset_s(addr, size, val, size);
    }
    return addr;
}

void CfFree(void *addr)
{
    if (addr != NULL) {
        free(addr);
    }
}

void StartRecordMallocNum(void)
{
    ResetRecordMallocNum();
    g_isRecordMallocNum = true;
}

void EndRecordMallocNum(void)
{
    ResetRecordMallocNum();
    g_isRecordMallocNum = false;
}

uint32_t GetMallocNum(void)
{
    return g_mallocNum;
}

void ResetRecordMallocNum(void)
{
    g_mallocNum = 0;
    g_mallocMockIndex = __INT32_MAX__;
}

void SetMockMallocIndex(uint32_t index)
{
    g_mallocMockIndex = index;
}