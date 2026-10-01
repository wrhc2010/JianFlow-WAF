import Busboy from "busboy";
import { XMLValidator } from "fast-xml-parser";

function validateJson(body: string): void {
  const pending = [{ value: JSON.parse(body) as unknown, depth: 0 }];
  let nodes = 0;
  while (pending.length) {
    const item = pending.pop()!;
    if (++nodes > 100000 || item.depth > 64) throw new Error("JSON 结构超过检测复杂度限制");
    if (item.value && typeof item.value === "object") {
      for (const child of Object.values(item.value)) pending.push({ value: child, depth: item.depth + 1 });
    }
  }
}

async function inspectMultipart(raw: Buffer, contentType: string, limit: number, fields?: Array<[string, string]>): Promise<string> {
  return new Promise((resolve, reject) => {
    const parser = Busboy({
      headers: { "content-type": contentType }, preservePath: true,
      limits: { fieldNameSize: 8192, fieldSize: limit, fileSize: limit, parts: 1000, headerPairs: 200 }
    });
    const text = [raw.toString("latin1")];
    let invalid = false;
    parser.on("field", (name, value, info) => {
      invalid ||= info.nameTruncated || info.valueTruncated;
      text.push(name, value);
      fields?.push([name, value]);
    });
    parser.on("file", (name, stream, info) => {
      text.push(name, info.filename, info.mimeType);
      const chunks: Buffer[] = [];
      stream.on("limit", () => { invalid = true; });
      stream.on("error", reject);
      stream.on("data", (chunk: Buffer) => chunks.push(chunk));
      stream.on("end", () => {
        const body = Buffer.concat(chunks);
        try {
          text.push(new TextDecoder("utf-8", { fatal: true }).decode(body));
        } catch {
          text.push(body.toString("latin1"));
        }
      });
    });
    parser.on("partsLimit", () => { invalid = true; });
    parser.on("error", reject);
    parser.on("close", () => {
      if (invalid) reject(new Error("multipart 字段或文件超过检测限制"));
      else resolve(text.join("\n"));
    });
    parser.end(raw);
  });
}

export async function inspectBody(raw: Buffer, contentType: string, limit: number, fields?: Array<[string, string]>): Promise<string> {
  if (!raw.length) return "";
  if (/^multipart\/form-data\b/i.test(contentType)) return inspectMultipart(raw, contentType, limit, fields);
  if (/^application\/octet-stream\b/i.test(contentType)) return raw.toString("latin1");
  const charset = /charset\s*=\s*"?([^";\s]+)/i.exec(contentType)?.[1] ?? "utf-8";
  const body = new TextDecoder(charset, { fatal: true }).decode(raw);
  if (/^application\/(?:[\w.-]+\+)?json\b/i.test(contentType)) validateJson(body);
  if (/^(?:application\/(?:[\w.-]+\+)?xml|text\/xml)\b/i.test(contentType)) {
    const result = XMLValidator.validate(body);
    if (result !== true) throw new Error(`XML 格式无效，行 ${result.err.line}`);
  }
  return body;
}
