import { useEffect, useState } from "react";
import { Edit3, Plus, Power, Save, Trash2, X, Play } from "lucide-react";
import type { SitePolicy, RuleException, AccessRule } from "@jev-waf/core";
export type { SitePolicy };
export const initialPolicy: SitePolicy = {
  enforcement: "enforce", strength: "medium", customThreshold: 0.5, disabledRuleIds: [], aiBehavior: "enforce",
  aiScope: "suspicious", aiFailureAction: "inherit", aiIncompleteAction: "local", aiBodyFields: [],
  rateLimit: { enabled: false, action: "block", requestsPerSecond: 20, burst: 40, maxConcurrent: 50, blockSeconds: 10, paths: [] }
};
type Api = <T>(path: string, init?: RequestInit) => Promise<T>;
type RuleOption = { id: string; name: string };
const split = (text: string) => text.split(",").map((part) => part.trim()).filter(Boolean);

export function PolicyFields({ policy, onChange, rateOnly = false, disabled = false, rules = [] }: {
  policy: SitePolicy; onChange: (policy: SitePolicy) => void; rateOnly?: boolean; disabled?: boolean; rules?: RuleOption[];
}) {
  const update = (patch: Partial<SitePolicy>) => onChange({ ...policy, ...patch });
  const limits = policy.rateLimit;
  const rate = (patch: Partial<SitePolicy["rateLimit"]>) => update({ rateLimit: { ...limits, ...patch } });
  return <fieldset className="policy-fields" disabled={disabled}>
    {rateOnly ? <>
      <label className="check-label"><input type="checkbox" checked={limits.enabled} onChange={(event) => rate({ enabled: event.target.checked })} />业务入口限速</label>
      <label className="field-label">CC 超限处理<select value={limits.action ?? "block"} onChange={(event) => rate({ action: event.target.value as "block" | "observe" })}><option value="block">阻断并临时封禁</option><option value="observe">仅记录</option></select></label>
      <div className="form-grid">
        <label className="field-label">每 IP 每秒请求<input type="number" min="0.1" max="10000" step="0.1" value={limits.requestsPerSecond} onChange={(event) => rate({ requestsPerSecond: Number(event.target.value) })} /></label>
        <label className="field-label">突发容量<input type="number" min="1" max="10000" value={limits.burst} onChange={(event) => rate({ burst: Number(event.target.value) })} /></label>
        <label className="field-label">每 IP 并发上限<input type="number" min="1" max="10000" value={limits.maxConcurrent} onChange={(event) => rate({ maxConcurrent: Number(event.target.value) })} /></label>
        <label className="field-label">临时封禁（秒）<input type="number" min="1" max="3600" value={limits.blockSeconds} onChange={(event) => rate({ blockSeconds: Number(event.target.value) })} /></label>
      </div>
      <div className="scoped-heading"><h3>关键路径</h3><button type="button" className="icon-button" aria-label="添加限速路径" title="添加限速路径" onClick={() => rate({ paths: [...limits.paths, { path: "/", requestsPerSecond: 5, burst: 10 }] })}><Plus size={16} /></button></div>
      {limits.paths.map((entry, index) => <div className="path-limit-row" key={index}>
        <label className="field-label">路径<input value={entry.path} onChange={(event) => rate({ paths: limits.paths.map((item, i) => i === index ? { ...item, path: event.target.value } : item) })} /></label>
        <label className="field-label">请求/秒<input type="number" min="0.1" step="0.1" value={entry.requestsPerSecond} onChange={(event) => rate({ paths: limits.paths.map((item, i) => i === index ? { ...item, requestsPerSecond: Number(event.target.value) } : item) })} /></label>
        <label className="field-label">突发<input type="number" min="1" value={entry.burst} onChange={(event) => rate({ paths: limits.paths.map((item, i) => i === index ? { ...item, burst: Number(event.target.value) } : item) })} /></label>
        <button type="button" className="icon-button" aria-label="删除限速路径" title="删除限速路径" onClick={() => rate({ paths: limits.paths.filter((_, i) => i !== index) })}><Trash2 size={15} /></button>
      </div>)}
    </> : <>
      <div className="form-grid">
        <label className="field-label">执行方式<select value={policy.enforcement} onChange={(event) => update({ enforcement: event.target.value as SitePolicy["enforcement"] })}><option value="enforce">阻断</option><option value="observe">观察</option></select></label>
        <label className="field-label">AI 工作方式<select value={policy.aiBehavior} onChange={(event) => update({ aiBehavior: event.target.value as SitePolicy["aiBehavior"] })}><option value="enforce">同步判断</option><option value="shadow">影子评估</option></select></label>
        <label className="field-label">AI 调用范围<select value={policy.aiScope} onChange={(event) => update({ aiScope: event.target.value as SitePolicy["aiScope"] })}><option value="suspicious">规则记录的可疑请求</option><option value="all">所有请求</option></select></label>
        <label className="field-label">AI 不可用<select value={policy.aiFailureAction} onChange={(event) => update({ aiFailureAction: event.target.value as SitePolicy["aiFailureAction"] })}><option value="inherit">按模式降级</option><option value="allow">继续本地结果</option><option value="block">拒绝请求</option></select></label>
        <label className="field-label">AI 检查不完整<select value={policy.aiIncompleteAction} onChange={(event) => update({ aiIncompleteAction: event.target.value as SitePolicy["aiIncompleteAction"] })}><option value="local">继续本地结果</option><option value="block">拒绝请求</option></select></label>
        <label className="field-label">拦截阈值<select value={policy.strength} onChange={(event) => update({ strength: event.target.value as SitePolicy["strength"] })}>{[["veryLow", "10%"], ["low", "30%"], ["medium", "50%"], ["high", "70%"], ["extreme", "90%"], ["custom", "自定义"]].map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      </div>
      {policy.strength === "custom" && <label className="field-label">自定义阈值（0-1）<input type="number" min="0" max="1" step="0.01" value={policy.customThreshold} onChange={(event) => update({ customThreshold: Number(event.target.value) })} /></label>}
      <label className="field-label">AI 允许出站正文路径<input value={policy.aiBodyFields.join(", ")} onChange={(event) => update({ aiBodyFields: split(event.target.value) })} /></label>
      <div className="policy-rule-list"><h3>本站停用规则</h3>{rules.map((rule) => <label className="check-label" key={rule.id}><input type="checkbox" checked={policy.disabledRuleIds.includes(rule.id)} onChange={(event) => update({ disabledRuleIds: event.target.checked ? [...policy.disabledRuleIds, rule.id] : policy.disabledRuleIds.filter((id) => id !== rule.id) })} /><span>{rule.id}<small>{rule.name}</small></span></label>)}</div>
    </>}
  </fieldset>;
}

export type ExceptionSeed = { method: string; path: string; ruleId: string; field: string; target: string };
export function ScopedRules({ api, siteId, kind, rules, seed, onSaved, onDirtyChange }: {
  api: Api; siteId: string; kind: "exceptions" | "access-rules"; rules: RuleOption[]; seed?: ExceptionSeed; onSaved?: () => void; onDirtyChange?: (dirty: boolean) => void;
}) {
  const [entries, setEntries] = useState<Array<RuleException | AccessRule>>([]);
  const [draft, setDraft] = useState<Record<string, unknown> | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [sample, setSample] = useState("");
  const [preview, setPreview] = useState("");
  useEffect(() => {
    onDirtyChange?.(draft !== null);
    const beforeUnload = (event: BeforeUnloadEvent) => {
      if (!draft) return;
      event.preventDefault(); event.returnValue = "";
    };
    window.addEventListener("beforeunload", beforeUnload);
    return () => { onDirtyChange?.(false); window.removeEventListener("beforeunload", beforeUnload); };
  }, [draft, onDirtyChange]);
  const path = `/api/v1/sites/${siteId}/${kind}`;
  const load = async () => {
    try {
      const data: Array<RuleException | AccessRule> = [];
      for (let offset = 0; offset < 500; offset += 100) {
        const page = await api<{ data: Array<RuleException | AccessRule> }>(`${path}?offset=${offset}&limit=100`);
        data.push(...page.data);
        if (page.data.length < 100) break;
      }
      setEntries(data);
    } catch (failure) { setError(failure instanceof Error ? failure.message : "配置加载失败"); }
  };
  const create = () => {
    setEditing(null); setPreview(""); setError("");
    setDraft({ name: "", method: seed?.method ?? "*", path: seed?.path ?? (kind === "exceptions" ? "/" : "*"),
      expiresAt: new Date(Date.now() + 7 * 86400000).toISOString(), enabled: true,
      ...(kind === "exceptions" ? { target: seed && ["body", "query", "header", "cookie"].includes(seed.target) ? seed.target : "body",
        selector: seed?.field ?? "", ruleIds: seed ? [seed.ruleId] : [], reason: "" } : { cidr: "", action: "block" }) });
  };
  useEffect(() => { void load(); if (seed) create(); }, [siteId, kind]);
  const update = (patch: Record<string, unknown>) => { setDraft((current) => ({ ...current, ...patch })); setPreview(""); };
  const save = async () => {
    try {
      await api(path + (editing ? `/${editing}` : ""), { method: editing ? "PATCH" : "POST", body: JSON.stringify(draft) });
      setDraft(null); setError(""); await load(); onSaved?.();
    } catch (failure) { setError(failure instanceof Error ? failure.message : "配置保存失败"); }
  };
  const mutate = async (entry: RuleException | AccessRule, remove = false) => {
    if (remove && !window.confirm(`确定删除“${entry.name}”吗？`)) return;
    try {
      await api(`${path}/${entry.id}`, { method: remove ? "DELETE" : "PATCH", ...(remove ? {} : { body: JSON.stringify({ enabled: !entry.enabled }) }) });
      await load(); onSaved?.();
    } catch (failure) { setError(failure instanceof Error ? failure.message : "配置更新失败"); }
  };
  return <div className="scoped-rules">
    <div className="scoped-heading"><h3>{kind === "exceptions" ? "精确规则例外" : "访问控制"}</h3><button type="button" className="secondary-button" onClick={create}><Plus size={15} />新增</button></div>
    {error && <div className="form-error">{error}</div>}
    {draft ? <div className="scoped-form">
      <div className="form-grid"><label className="field-label">名称<input value={String(draft.name)} onChange={(event) => update({ name: event.target.value })} /></label>
        <label className="field-label">方法<select value={String(draft.method)} onChange={(event) => update({ method: event.target.value })}>{["*", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((method) => <option key={method}>{method}</option>)}</select></label></div>
      <label className="field-label">完整路径<input value={String(draft.path)} onChange={(event) => update({ path: event.target.value })} /></label>
      {kind === "exceptions" ? <>
        <div className="form-grid"><label className="field-label">目标<select value={String(draft.target)} onChange={(event) => update({ target: event.target.value })}>{["body", "query", "header", "cookie"].map((target) => <option key={target}>{target}</option>)}</select></label>
          <label className="field-label">字段路径<input value={String(draft.selector)} onChange={(event) => update({ selector: event.target.value })} /></label></div>
        <label className="field-label">规则<select multiple value={draft.ruleIds as string[]} onChange={(event) => update({ ruleIds: Array.from(event.target.selectedOptions, (option) => option.value) })}>{rules.map((rule) => <option value={rule.id} key={rule.id}>{rule.id} · {rule.name}</option>)}</select></label>
        <label className="field-label">原因<textarea value={String(draft.reason)} onChange={(event) => update({ reason: event.target.value })} /></label>
      </> : <div className="form-grid"><label className="field-label">IP / CIDR<input value={String(draft.cidr)} onChange={(event) => update({ cidr: event.target.value })} /></label>
        <label className="field-label">动作<select value={String(draft.action)} onChange={(event) => update({ action: event.target.value })}><option value="block">拒绝</option><option value="skip-detection">仅跳过检测</option></select></label></div>}
      <label className="field-label">有效期<input type="datetime-local" value={new Date(String(draft.expiresAt)).toLocaleString("sv-SE").slice(0, 16).replace(" ", "T")} onChange={(event) => { if (event.target.value) update({ expiresAt: new Date(event.target.value).toISOString() }); }} /></label>
      <label className="check-label"><input type="checkbox" checked={Boolean(draft.enabled)} onChange={(event) => update({ enabled: event.target.checked })} />启用</label>
      {kind === "exceptions" && <><label className="field-label">回放样本（JSON）<textarea value={sample} onChange={(event) => setSample(event.target.value)} /></label>
        <button type="button" className="secondary-button" onClick={async () => {
          try {
            const result = await api<{ before: Array<{ ruleId: string }>; after: Array<{ ruleId: string }> }>(`/api/v1/sites/${siteId}/exception-previews`, { method: "POST", body: JSON.stringify({ ...JSON.parse(sample), exception: draft }) });
            setPreview(`原命中：${result.before.map((rule) => rule.ruleId).join(", ") || "无"}；应用后：${result.after.map((rule) => rule.ruleId).join(", ") || "无"}`);
          } catch (failure) { setError(failure instanceof Error ? failure.message : "回放失败"); }
        }} disabled={!sample.trim()}><Play size={15} />回放样本</button></>}
      {preview && <div className="inline-status">{preview}</div>}
      <div className="panel-actions"><button type="button" className="secondary-button" onClick={() => setDraft(null)}><X size={15} />取消</button><button type="button" className="primary-button" onClick={() => void save()}><Save size={15} />保存{kind === "exceptions" ? "例外" : "访问控制"}</button></div>
    </div> : <div className="scoped-list">{entries.length ? entries.map((entry) => <div className="scoped-row" key={entry.id}>
      <div><strong>{entry.name}</strong><small>{entry.method} {entry.path}</small><small>{"ruleIds" in entry ? `${entry.target}:${entry.selector} · ${entry.ruleIds.join(", ")}` : `${entry.cidr} · ${entry.action}`}</small>
        <small>{!entry.enabled ? "已停用" : Date.parse(entry.expiresAt) <= Date.now() ? "已过期" : "生效中"} · {new Date(entry.expiresAt).toLocaleString()}</small></div>
      <div className="panel-actions"><button type="button" className="icon-button" title="编辑" aria-label="编辑配置" onClick={() => { const { id, siteId: _site, ...editable } = entry; setEditing(id); setDraft(editable as unknown as Record<string, unknown>); }}><Edit3 size={15} /></button>
        <button type="button" className="icon-button" title="切换启用" aria-label="切换启用" onClick={() => void mutate(entry)}><Power size={15} /></button><button type="button" className="icon-button" title="删除" aria-label="删除配置" onClick={() => void mutate(entry, true)}><Trash2 size={15} /></button></div>
    </div>) : <div className="empty-state">暂无{kind === "exceptions" ? "规则例外" : "访问控制"}</div>}</div>}
  </div>;
}
