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

// import buffer from "@ohos.buffer"

namespace utils {
export function hexStrToUint8Array(data: string): Uint8Array {
  // return new Uint8Array(buffer.from(data, 'hex').buffer);
  if (data.length % 2 !== 0) {
    throw new Error("Invalid hex string");
  }
  const array = new Uint8Array(data.length / 2);
  for (let i = 0; i < data.length; i += 2) {
    array[i / 2] = parseInt(data.substring(i, i + 2), 16);
  }
  return array;
}

export function stringToUint8Array(str: string): Uint8Array {
  // return new Uint8Array(buffer.from(str, 'utf-8').buffer);
  const array = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    array[i] = str.charCodeAt(i);
  }
  return array;
}

export function uint8ArrayToHexStr(data: Uint8Array): string {
  // return buffer.from(data).toString('hex').toUpperCase();
  let str = '';
  for (let i = 0; i < data.length; i++) {
    let num: Number = new Number(data[i]);
    str += num.toString(16).padStart(2, '0');
  }
  return str;
}

export function uint8ArrayToString(data: Uint8Array): string {
  // return buffer.from(data).toString('utf-8').toUpperCase();
  let str = '';
  for (let i = 0; i < data.length; i++) {
    str += String.fromCharCode(data[i]);
  }
  return str;
}

export function doFullGC(): void {
  try {
      GC.waitForFinishGC(GC.startGC(GC.Cause.FULL, GC.IN_PLACE_MODE));
  } catch (err) {
      assertTrue(false, "Unexpected exception during GC");
  }
  Coroutine.Schedule();
}

export function stopTaskPool(): void {
  CoroutineExtras.stopTaskpool();
}
} // namespace utils

export default utils;
