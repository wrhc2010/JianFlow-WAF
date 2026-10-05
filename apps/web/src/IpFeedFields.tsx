import { useState } from "react";
import { Search, Upload } from "lucide-react";

export function IpFeedFields({ onApply, preview }: { onApply: (target: "whitelistCidrs" | "maliciousIpCidrs", values: string[]) => void; preview: (content: string, format: string) => Promise<string[]> }) {
  const [target, setTarget] = useState<"whitelistCidrs" | "maliciousIpCidrs">("maliciousIpCidrs");
  const [format, setFormat] = useState("text");
  const [content, setContent] = useState("");
  const [entries, setEntries] = useState<string[] | null>(null);
  const [error, setError] = useState("");
  return <div className="feed-import-fields">
    <div className="form-grid compact-grid"><label className="field-label">导入到<select value={target} onChange={(event) => setTarget(event.target.value as typeof target)}><option value="maliciousIpCidrs">恶意 IP 库</option><option value="whitelistCidrs">IP 白名单</option></select></label><label className="field-label">文件格式<select value={format} onChange={(event) => { setFormat(event.target.value); setEntries(null); }}><option value="text">CIDR 文本</option><option value="json">JSON</option><option value="csv">CSV 第一列</option><option value="stix">STIX Bundle</option><option value="taxii">TAXII JSON 响应</option></select></label></div>
    <label className="file-upload-label"><Upload size={16} /><span>选择 IP 库文件</span><input type="file" accept=".txt,.json,.csv" onChange={async (event) => {
      const file = event.target.files?.[0]; event.target.value = ""; if (!file) return;
      try { if (file.size > 1024 * 1024) throw new Error("文件不能超过 1 MB"); setContent(new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer())); setEntries(null); setError(""); }
      catch (failure) { setError(failure instanceof Error ? failure.message : "文件编码无效"); }
    }} /></label>
    <textarea rows={3} aria-label="IP 库导入内容" value={content} onChange={(event) => { setContent(event.target.value); setEntries(null); }} />
    <div className="settings-actions"><button className="secondary-button" disabled={!content.trim()} onClick={async () => { try { setEntries(await preview(content, format)); setError(""); } catch (failure) { setError(failure instanceof Error ? failure.message : "预览失败"); } }}><Search size={15} />预览 IP 库</button><button className="secondary-button" disabled={!entries?.length} onClick={() => { onApply(target, entries!); setEntries(null); setContent(""); }}><Upload size={15} />加入草稿</button></div>
    {entries && <div className="inline-status">有效地址 {entries.length} 项{entries.length ? ` · ${entries.slice(0, 3).join("，")}` : ""}</div>}
    {error && <div className="form-error" role="alert">{error}</div>}
  </div>;
}
