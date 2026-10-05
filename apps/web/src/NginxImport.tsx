import { useEffect, useState } from "react";
import { Search, Upload } from "lucide-react";

type Preview = { valid: boolean; sites: Array<{ name: string; listenPort: number; upstreamUrl?: string; upstreamPool?: unknown[]; redirect?: { statusCode: number; location: string } }>; warnings: string[]; errors: string[] };
type ImportRecord = { id: string; createdAt: string; digest: string; ports: number[] };
export function NginxImport({ request, onImported }: { request: <T>(path: string, options?: RequestInit) => Promise<T>; onImported: () => void }) {
  const [content, setContent] = useState("");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState("");
  const [history, setHistory] = useState<ImportRecord[]>([]);
  const loadHistory = async () => { setHistory((await request<{ data: ImportRecord[] }>("/api/v1/nginx/imports")).data); };
  useEffect(() => { void loadHistory().catch(() => {}); }, []);
  return <details className="nginx-import-section"><summary>Nginx 配置导入</summary>
    <label className="file-upload-label"><Upload size={16} /><span>选择 .conf 文件</span><input type="file" accept=".conf,text/plain" onChange={async (event) => { const file = event.target.files?.[0]; event.target.value = ""; if (!file) return; try { if (file.size > 1024 * 1024) throw new Error("配置不能超过 1 MB"); setContent(new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer())); setPreview(null); setError(""); } catch (failure) { setError(failure instanceof Error ? failure.message : "读取失败"); } }} /></label>
    <textarea rows={5} aria-label="Nginx 配置内容" value={content} onChange={(event) => { setContent(event.target.value); setPreview(null); }} />
    <div className="settings-actions"><button className="secondary-button" disabled={!content.trim()} onClick={async () => { try { setPreview(await request<Preview>("/api/v1/nginx/import/preview", { method: "POST", body: JSON.stringify({ content }) })); setError(""); } catch (failure) { setError(failure instanceof Error ? failure.message : "预览失败"); } }}><Search size={15} />预览站点</button><button className="primary-button" disabled={!preview?.valid} onClick={async () => { try { await request("/api/v1/nginx/import", { method: "POST", body: JSON.stringify({ content, confirm: true }) }); setContent(""); setPreview(null); setError(""); await loadHistory(); onImported(); } catch (failure) { setError(failure instanceof Error ? failure.message : "导入失败"); } }}><Upload size={15} />确认导入</button></div>
    {preview && <div className="nginx-preview">{preview.sites.map((site) => <div key={site.listenPort}><strong>{site.name} · :{site.listenPort}</strong><span>{site.redirect ? `${site.redirect.statusCode} ${site.redirect.location}` : `${site.upstreamUrl}${site.upstreamPool ? ` · ${site.upstreamPool.length} 个节点` : ""}`}</span></div>)}{[...preview.warnings, ...preview.errors].map((message, index) => <p key={index}>{message}</p>)}</div>}
    {error && <div className="form-error" role="alert">{error}</div>}
    {history.length > 0 && <div className="nginx-preview" aria-label="导入历史">{history.slice(0, 10).map((record) => <div key={record.id}><strong>{new Date(record.createdAt).toLocaleString()} · {record.ports.map((port) => `:${port}`).join(", ")}</strong><span title={record.digest}>SHA-256 {record.digest.slice(0, 16)}</span></div>)}</div>}
  </details>;
}
