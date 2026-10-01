import { RE2 } from "re2-wasm";

const cache = new Map<string, RE2>();
export const MAX_PATTERN_LENGTH = 8192;

export function compileSafeRegex(pattern: string, caseSensitive = false): RE2 {
  if (pattern.length > MAX_PATTERN_LENGTH) throw new Error("正则表达式不能超过 8192 个字符");
  const key = `${caseSensitive ? "u" : "iu"}:${pattern}`;
  let compiled = cache.get(key);
  if (!compiled) {
    compiled = new RE2(pattern, caseSensitive ? "u" : "iu");
    if (cache.size >= 512) cache.delete(cache.keys().next().value!);
    cache.set(key, compiled);
  }
  return compiled;
}
