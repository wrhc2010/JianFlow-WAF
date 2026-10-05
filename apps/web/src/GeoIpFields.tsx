import { useEffect, useState } from "react";
import { Save, Upload, X } from "lucide-react";

type DatabaseStatus = { ready: boolean; databaseType?: string; buildDate?: string };
type GeoStatus = { city: DatabaseStatus; asn: DatabaseStatus };

export function GeoIpFields() {
  const [status, setStatus] = useState<GeoStatus>();
  const [kind, setKind] = useState<"city" | "asn">("city");
  const [file, setFile] = useState<File>();
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    void fetch("/api/v1/geoip", { credentials: "include" }).then(async (response) => {
      if (!response.ok) throw new Error("GeoIP 状态读取失败");
      setStatus(await response.json());
    }).catch((error: Error) => setMessage(error.message));
  }, []);
  async function save() {
    if (!file) return;
    setBusy(true); setMessage("");
    try {
      const response = await fetch(`/api/v1/geoip/${kind}`, { method: "PUT", credentials: "include", headers: { "content-type": "application/octet-stream", "x-filename": "database.mmdb" }, body: file });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? "GeoIP 保存失败");
      setStatus(result); setFile(undefined); setMessage("GeoIP 已更新");
    } catch (error) { setMessage(error instanceof Error ? error.message : "GeoIP 保存失败"); }
    finally { setBusy(false); }
  }
  return <div className="geoip-fields">
    <div className="site-details">{(["city", "asn"] as const).map((key) => <div key={key}><span>{key === "city" ? "City 数据库" : "ASN 数据库"}</span><strong>{status?.[key].ready ? status[key].databaseType : "未加载"}</strong>{status?.[key].buildDate && <small>{new Date(status[key].buildDate!).toLocaleDateString()}</small>}</div>)}</div>
    <label className="field-label">数据库类型<select value={kind} disabled={busy} onChange={(event) => { setKind(event.target.value as typeof kind); setFile(undefined); setMessage(""); }}><option value="city">City</option><option value="asn">ASN</option></select></label>
    <label className="file-button secondary-button"><Upload size={15} />选择 MMDB<input type="file" accept=".mmdb" disabled={busy} onChange={(event) => {
      const selected = event.target.files?.[0]; event.target.value = "";
      if (!selected) return;
      if (!selected.name.toLowerCase().endsWith(".mmdb") || selected.size > 128 * 1024 * 1024) { setMessage("请选择 128 MB 以内的 .mmdb 文件"); return; }
      setFile(selected); setMessage("");
    }} /></label>
    {file && <p className="panel-meta">{file.name} · {(file.size / 1024 / 1024).toFixed(1)} MB · 未保存</p>}
    <div className="settings-actions"><button className="secondary-button" disabled={!file || busy} onClick={() => setFile(undefined)}><X size={15} />取消</button><button className="primary-button" disabled={!file || busy} onClick={() => void save()}><Save size={15} />{busy ? "保存中" : "保存 GeoIP"}</button></div>
    {message && <p role="status" className="panel-meta">{message}</p>}
  </div>;
}
