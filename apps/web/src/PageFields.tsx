import { useState } from "react";
import { Upload } from "lucide-react";

export type PageConfig = { source: "default" | "file" | "inline"; html?: string; filePath?: string; statusCode: number };
export type WaitRoomConfig = { enabled: boolean; maxActive: number; maxQueue: number; timeoutSeconds: number; page?: PageConfig; fullAction?: "reject" | "unavailable" };

export function PageFields({ title, page, onChange }: { title: string; page: PageConfig; onChange: (page: PageConfig) => void }) {
  const [error, setError] = useState("");
  return <fieldset className="page-fields">
    <legend>{title}</legend>
    <div className="form-grid compact-grid">
      <label className="field-label">页面来源<select value={page.source} onChange={(event) => { setError(""); onChange({ source: event.target.value as PageConfig["source"], statusCode: page.statusCode }); }}><option value="default">默认页面</option><option value="inline">上传 HTML</option><option value="file">挂载文件</option></select></label>
      <label className="field-label">HTTP 状态码<input type="number" min={400} max={599} value={page.statusCode} onChange={(event) => onChange({ ...page, statusCode: Number(event.target.value) })} /></label>
    </div>
    {page.source === "file" && <label className="field-label">pages 目录内的相对路径<input value={page.filePath ?? ""} placeholder="maintenance.html" onChange={(event) => onChange({ ...page, filePath: event.target.value })} /></label>}
    {page.source === "inline" && <>
      <label className="file-upload-label"><Upload size={16} /><span>HTML 文件</span><input type="file" accept=".html,text/html" onChange={async (event) => {
        const file = event.target.files?.[0];
        event.target.value = "";
        if (!file) return;
        try {
          if (!file.name.toLowerCase().endsWith(".html") || !file.size || file.size > 512 * 1024) throw new Error("请选择不超过 512 KB 的 .html 文件");
          const html = new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer());
          if (html.includes("\0")) throw new Error("文件包含无效字符");
          onChange({ source: "inline", statusCode: page.statusCode, html }); setError("");
        } catch (failure) { setError(failure instanceof Error ? failure.message : "文件必须使用 UTF-8 编码"); }
      }} /></label>
      {page.html && <iframe className="page-preview" sandbox="" title={`${title}预览`} srcDoc={page.html} />}
    </>}
    {error && <div className="form-error" role="alert">{error}</div>}
  </fieldset>;
}
