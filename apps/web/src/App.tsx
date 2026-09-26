import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Bot,
  Check,
  ChevronDown,
  CircleGauge,
  FileCode2,
  Filter,
  Gauge,
  Globe2,
  LockKeyhole,
  LogOut,
  Network,
  PanelLeft,
  Play,
  RefreshCw,
  Save,
  Search,
  Server,
  Shield,
  SlidersHorizontal,
  TerminalSquare,
  X
} from "lucide-react";

type Mode = "ai" | "traditional" | "hybrid";
type Strength = "low" | "medium" | "high" | "extreme" | "custom";
type Settings = {
  mode: Mode;
  strength: Strength;
  customThreshold: number;
  model: string;
  aiTimeoutMs: number;
  aiBodyLimit: number;
  upstreamUrl: string;
  apiKeyConfigured: boolean;
};
type Rule = {
  id: string;
  name: string;
  source: string;
  category: string;
  severity: string;
  target: string;
  operator: string;
  pattern: string;
  action: "block" | "log";
  enabled: boolean;
};
type EventRecord = {
  id: string | number;
  requestId: string;
  action: string;
  mode: Mode;
  method: string;
  path: string;
  ip?: string;
  statusCode?: number;
  score?: number;
  threshold?: number;
  reason: string;
  matchedRules: Array<{ ruleId: string; name: string; category: string; severity: string }>;
  ai?: { model: string; noul: number; latencyMs: number; available: boolean; error?: string };
  partialInspection: boolean;
  createdAt: string;
};

const initialSettings: Settings = {
  mode: "hybrid",
  strength: "medium",
  customThreshold: 0.7,
  model: "typesafe/jev-1.13",
  aiTimeoutMs: 2000,
  aiBodyLimit: 32768,
  upstreamUrl: "http://127.0.0.1:9000",
  apiKeyConfigured: false
};

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    credentials: "include",
    headers: {
      ...(init?.body ? { "content-type": "application/json" } : {}),
      ...(init?.headers ?? {})
    },
    ...init
  });
  if (!response.ok) {
    throw new Error((await response.json().catch(() => null))?.detail ?? `HTTP ${response.status}`);
  }
  return response.json() as Promise<T>;
}

function formatTime(value: string): string {
  return new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(value));
}

function scoreLabel(value?: number): string {
  return value === undefined ? "—" : `${Math.round(value * 100)}%`;
}

function App() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [section, setSection] = useState("overview");

  useEffect(() => {
    api<{ username: string }>("/api/v1/auth/me").then(() => setAuthenticated(true)).catch(() => setAuthenticated(false));
  }, []);

  if (authenticated === null) {
    return <div className="boot-screen"><div className="boot-mark">J</div><span>正在连接控制平面</span></div>;
  }

  if (!authenticated) {
    return (
      <LoginScreen
        username={username}
        password={password}
        error={loginError}
        onUsername={setUsername}
        onPassword={setPassword}
        onSubmit={async (event) => {
          event.preventDefault();
          setLoginError("");
          try {
            await api("/api/v1/auth/login", { method: "POST", body: JSON.stringify({ username, password }) });
            setAuthenticated(true);
          } catch (error) {
            setLoginError(error instanceof Error ? error.message : "登录失败");
          }
        }}
      />
    );
  }

  return (
    <Console
      section={section}
      onSection={setSection}
      onLogout={async () => {
        await api("/api/v1/auth/logout", { method: "POST" });
        setAuthenticated(false);
      }}
    />
  );
}

function LoginScreen(props: {
  username: string;
  password: string;
  error: string;
  onUsername: (value: string) => void;
  onPassword: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <main className="login-page">
      <div className="login-grid" />
      <section className="login-panel">
        <div className="brand-lockup"><div className="brand-glyph">J</div><div><strong>鉴流 · JianFlow WAF</strong><span>防护控制台</span></div></div>
        <div className="login-rule" />
        <p className="eyebrow">CONTROL PLANE / LOCAL ADMIN</p>
        <h1>登录控制台</h1>
        <p className="muted">管理流量入口、规则引擎与 Jev AI 判断。</p>
        <form onSubmit={props.onSubmit} className="login-form">
          <label>管理员账号<input value={props.username} onChange={(event) => props.onUsername(event.target.value)} autoComplete="username" /></label>
          <label>管理员密码<input type="password" value={props.password} onChange={(event) => props.onPassword(event.target.value)} autoComplete="current-password" /></label>
          {props.error && <div className="form-error"><AlertTriangle size={15} />{props.error}</div>}
          <button className="primary-button full-width" type="submit"><LockKeyhole size={16} />进入控制台</button>
        </form>
        <div className="login-foot"><span>默认账号由服务端环境变量配置</span><span className="status-dot">系统待命</span></div>
      </section>
    </main>
  );
}

function Console({ section, onSection, onLogout }: { section: string; onSection: (value: string) => void; onLogout: () => void }) {
  const [collapsed, setCollapsed] = useState(false);
  const nav = [
    { id: "overview", label: "总览", icon: CircleGauge },
    { id: "events", label: "事件中心", icon: Activity },
    { id: "rules", label: "规则库", icon: FileCode2 },
    { id: "sites", label: "站点与上游", icon: Network },
    { id: "settings", label: "防护策略", icon: SlidersHorizontal }
  ];
  return (
    <div className="app-shell">
      <aside className={`sidebar ${collapsed ? "collapsed" : ""}`}>
        <div className="sidebar-top"><div className="brand-glyph">J</div>{!collapsed && <div className="brand-copy"><strong>鉴流 · JianFlow</strong><span>SECURITY CONSOLE</span></div>}</div>
        <nav className="nav-list">
          {nav.map((item) => {
            const Icon = item.icon;
            return <button key={item.id} className={`nav-item ${section === item.id ? "active" : ""}`} onClick={() => onSection(item.id)} title={item.label}><Icon size={17} />{!collapsed && <span>{item.label}</span>}</button>;
          })}
        </nav>
        <div className="sidebar-bottom">
          {!collapsed && <div className="node-card"><div className="node-card-head"><span className="status-dot">运行中</span><span>单节点</span></div><strong>jianflow-local</strong><span>HTTP :8080 / API :4000</span></div>}
          <button className="nav-item" onClick={onLogout} title="退出登录"><LogOut size={17} />{!collapsed && <span>退出登录</span>}</button>
        </div>
      </aside>
      <main className="main-area">
        <header className="topbar">
          <button className="icon-button" onClick={() => setCollapsed(!collapsed)} aria-label="折叠导航"><PanelLeft size={17} /></button>
          <div className="breadcrumb"><span>JianFlow WAF</span><ArrowRight size={13} /><strong>{navLabel(section)}</strong></div>
          <div className="topbar-right"><span className="live-pill"><span className="status-dot" />防护已启用</span><span className="topbar-time">{new Date().toLocaleDateString("zh-CN")}</span></div>
        </header>
        <div className="content">
          {section === "overview" && <Overview onSection={onSection} />}
          {section === "events" && <Events />}
          {section === "rules" && <Rules />}
          {section === "sites" && <Sites />}
          {section === "settings" && <SettingsPanel />}
        </div>
      </main>
    </div>
  );
}

function navLabel(section: string): string {
  return { overview: "总览", events: "事件中心", rules: "规则库", sites: "站点与上游", settings: "防护策略" }[section] ?? "总览";
}

function useConsoleData() {
  const [settings, setSettings] = useState<Settings>(initialSettings);
  const [summary, setSummary] = useState<Record<string, number>>({});
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);

  const refresh = async () => {
    setLoading(true);
    try {
      const [nextSettings, nextSummary, nextEvents, nextRules] = await Promise.all([
        api<Settings>("/api/v1/settings"),
        api<Record<string, number>>("/api/v1/dashboard/summary"),
        api<{ data: EventRecord[] }>("/api/v1/events?limit=50"),
        api<{ data: Rule[] }>("/api/v1/rules")
      ]);
      setSettings(nextSettings);
      setSummary(nextSummary);
      setEvents(nextEvents.data);
      setRules(nextRules.data);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void refresh(); }, []);
  return { settings, setSettings, summary, events, setEvents, rules, setRules, loading, refresh };
}

function Overview({ onSection }: { onSection: (section: string) => void }) {
  const { settings, summary, events, loading, refresh } = useConsoleData();
  const modeLabel = { ai: "AI 判断", traditional: "传统规则", hybrid: "混合模式" };
  return (
    <section>
      <PageHeading eyebrow="LIVE PROTECTION" title="防护总览" description="从请求进入到最终决策，查看当前 WAF 的实时状态。" action={<button className="secondary-button" onClick={() => void refresh()}><RefreshCw size={15} />刷新</button>} />
      <div className="signal-strip"><div><span className="signal-label">当前防护模式</span><strong>{modeLabel[settings.mode]}</strong></div><div><span className="signal-label">Jev 模型</span><strong>{settings.model}</strong></div><div><span className="signal-label">拦截阈值</span><strong>{settings.strength === "custom" ? `${Math.round(settings.customThreshold * 100)}%` : settings.strength}</strong></div><div><span className="signal-label">AI 状态</span><strong className={settings.apiKeyConfigured ? "text-green" : "text-amber"}>{settings.apiKeyConfigured ? "已连接" : "未配置"}</strong></div></div>
      <div className="metric-grid">
        <Metric label="已检查请求" value={summary.total ?? 0} detail="当前保留窗口" icon={Activity} />
        <Metric label="已拦截" value={summary.blocked ?? 0} detail="规则 + Jev" icon={Shield} accent="red" />
        <Metric label="已放行" value={summary.allowed ?? 0} detail="低风险请求" icon={Check} accent="green" />
        <Metric label="AI 降级" value={summary.aiUnavailable ?? 0} detail="Jev 不可用事件" icon={AlertTriangle} accent="amber" />
      </div>
      <div className="two-column">
        <Panel title="决策链" action={<button className="text-button" onClick={() => onSection("settings")}>调整策略 <ArrowRight size={14} /></button>}>
          <DecisionPipeline mode={settings.mode} />
        </Panel>
        <Panel title="最近事件" action={<button className="text-button" onClick={() => onSection("events")}>查看全部 <ArrowRight size={14} /></button>}>
          {loading ? <LoadingRows count={4} /> : <EventList events={events.slice(0, 4)} />}
        </Panel>
      </div>
    </section>
  );
}

function Events() {
  const { events, loading, refresh } = useConsoleData();
  const [filter, setFilter] = useState("all");
  const visible = useMemo(() => events.filter((event) => filter === "all" || event.action === filter), [events, filter]);
  return (
    <section>
      <PageHeading eyebrow="REQUEST TELEMETRY" title="事件中心" description="每个请求的规则命中、AI 概率和最终动作都可追溯。" action={<button className="secondary-button" onClick={() => void refresh()}><RefreshCw size={15} />刷新</button>} />
      <div className="toolbar"><div className="search-box"><Search size={16} /><input placeholder="搜索路径或 request ID" /></div><div className="segmented">{["all", "block", "allow", "error"].map((value) => <button key={value} className={filter === value ? "selected" : ""} onClick={() => setFilter(value)}>{value === "all" ? "全部" : value === "block" ? "已拦截" : value === "allow" ? "已放行" : "错误"}</button>)}</div><button className="icon-button" title="筛选"><Filter size={16} /></button></div>
      <Panel title={`${visible.length} 条事件`} action={<span className="panel-meta">最近 50 条</span>}>
        {loading ? <LoadingRows count={7} /> : <EventTable events={visible} />}
      </Panel>
    </section>
  );
}

function Rules() {
  const { rules, loading, setRules, refresh } = useConsoleData();
  const [testPath, setTestPath] = useState("/search?q=union+select+password+from+users");
  const [testResult, setTestResult] = useState<string>("");
  const toggleRule = async (rule: Rule) => {
    const updated = await api<Rule>(`/api/v1/rules/${rule.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !rule.enabled }) });
    setRules((current) => current.map((item) => item.id === updated.id ? updated : item));
  };
  return (
    <section>
      <PageHeading eyebrow="RULE ENGINE" title="规则库" description="管理 OWASP CRS 风格子集与自定义高置信度规则。" action={<button className="secondary-button" onClick={() => void refresh()}><RefreshCw size={15} />刷新</button>} />
      <div className="two-column rules-layout">
        <Panel title="已加载规则" action={<span className="panel-meta">{rules.filter((rule) => rule.enabled).length} / {rules.length} 启用</span>}>
          {loading ? <LoadingRows count={6} /> : <div className="rule-list">{rules.map((rule) => <div className="rule-row" key={rule.id}><div className={`severity-mark ${rule.severity}`} /><div className="rule-main"><strong>{rule.name}</strong><span>{rule.id} · {rule.category}</span></div><span className="source-tag">{rule.source}</span><button className={`toggle ${rule.enabled ? "on" : ""}`} onClick={() => void toggleRule(rule)} aria-label={`切换 ${rule.name}`}><span /></button></div>)}</div>}
        </Panel>
        <Panel title="规则测试" action={<TerminalSquare size={16} className="panel-icon" />}>
          <label className="field-label">请求路径<input value={testPath} onChange={(event) => setTestPath(event.target.value)} /></label>
          <button className="primary-button" onClick={async () => { const url = new URL(testPath, "http://test.local"); const result = await api<{ matches: Rule[] }>("/api/v1/rules/test", { method: "POST", body: JSON.stringify({ method: "GET", path: url.pathname, query: url.search, headers: {} }) }); setTestResult(result.matches.length ? `命中 ${result.matches.length} 条规则：${result.matches.map((match) => match.name).join("、")}` : "未命中规则"); }}><Play size={15} />执行测试</button>
          {testResult && <div className={`test-result ${testResult.startsWith("未") ? "good" : "bad"}`}><span>{testResult.startsWith("未") ? <Check size={15} /> : <AlertTriangle size={15} />}</span>{testResult}</div>}
          <div className="note-box"><span className="note-title">规则范围</span><p>内置规则覆盖 SQL 注入、XSS、路径穿越、命令注入和敏感扫描路径。自定义规则通过 API 添加，禁止执行任意脚本。</p></div>
        </Panel>
      </div>
    </section>
  );
}

function Sites() {
  const { settings, setSettings, loading } = useConsoleData();
  const [saved, setSaved] = useState(false);
  return (
    <section>
      <PageHeading eyebrow="TRAFFIC ENTRY" title="站点与上游" description="配置 WAF 保护的上游服务和数据面入口。" />
      <div className="site-banner"><div className="site-icon"><Globe2 size={22} /></div><div><strong>默认站点</strong><span>当前所有 8080 流量使用该上游</span></div><span className="status-badge green">运行中</span></div>
      <Panel title="默认上游">
        <div className="form-grid">
          <label className="field-label">上游地址<input value={settings.upstreamUrl} onChange={(event) => setSettings({ ...settings, upstreamUrl: event.target.value })} /></label>
          <label className="field-label">监听入口<input value="http://0.0.0.0:8080" readOnly /></label>
          <label className="field-label">WebSocket<input value="支持握手透传" readOnly /></label>
          <label className="field-label">检查上限<input value="256 KB / 请求" readOnly /></label>
        </div>
        <div className="panel-actions"><button className="primary-button" disabled={loading} onClick={async () => { await api("/api/v1/settings", { method: "PATCH", body: JSON.stringify({ upstreamUrl: settings.upstreamUrl }) }); setSaved(true); setTimeout(() => setSaved(false), 2200); }}><Save size={15} />保存上游</button>{saved && <span className="save-confirm"><Check size={14} />已保存</span>}</div>
      </Panel>
      <div className="two-column">
        <Panel title="数据面状态"><StatusLine icon={Server} label="反向代理" value="HTTP :8080" state="good" /><StatusLine icon={Network} label="上游连接" value={settings.upstreamUrl} state="good" /><StatusLine icon={Globe2} label="HTTPS 终止" value="待配置证书" state="warn" /></Panel>
        <Panel title="部署提示"><div className="note-box"><span className="note-title">Linux / Docker</span><p>将上游服务地址设置为 Compose 网络内的服务名，例如 <code>http://app:8080</code>。HTTPS 证书目录在生产环境挂载到 WAF 容器。</p></div></Panel>
      </div>
    </section>
  );
}

function SettingsPanel() {
  const { settings, setSettings, loading } = useConsoleData();
  const [jevStatus, setJevStatus] = useState("");
  const save = async () => {
    await api("/api/v1/settings", { method: "PATCH", body: JSON.stringify(settings) });
    setJevStatus("策略已保存");
    setTimeout(() => setJevStatus(""), 2200);
  };
  return (
    <section>
      <PageHeading eyebrow="PROTECTION POLICY" title="防护策略" description="决定传统规则、Jev AI 和故障降级的执行方式。" action={<button className="primary-button" disabled={loading} onClick={() => void save()}><Save size={15} />保存策略</button>} />
      <div className="two-column settings-layout">
        <Panel title="防护模式">
          <div className="mode-options">{[
            ["hybrid", "混合模式", "先规则过滤，再由 Jev 复核", Network],
            ["ai", "AI 判断", "由 Jev 判断请求恶意概率", Bot],
            ["traditional", "传统规则", "仅使用本地规则引擎", FileCode2]
          ].map(([value, label, detail, Icon]) => {
            const ModeIcon = Icon as typeof Network;
            return <button key={value as string} className={`mode-option ${settings.mode === value ? "selected" : ""}`} onClick={() => setSettings({ ...settings, mode: value as Mode })}><span className="mode-option-icon"><ModeIcon size={17} /></span><span><strong>{label as string}</strong><small>{detail as string}</small></span>{settings.mode === value && <Check size={16} className="check-icon" />}</button>;
          })}</div>
          <div className="divider" />
          <label className="field-label">Jev 模型<select value={settings.model} onChange={(event) => setSettings({ ...settings, model: event.target.value })}><option value="typesafe/jev-1.13">typesafe/jev-1.13（固定版本）</option><option value="~typesafe/jev-latest">~typesafe/jev-latest（跟随最新）</option></select></label>
          <div className="api-state"><span className={`status-dot ${settings.apiKeyConfigured ? "" : "amber"}`} /><span>{settings.apiKeyConfigured ? "OpenRouter key 已配置" : "OpenRouter key 未配置"}</span><span className="panel-meta">只在服务端读取</span></div>
          <button className="secondary-button" onClick={async () => { const result = await api<{ available: boolean; error?: string; latencyMs: number }>("/api/v1/settings/test-jev", { method: "POST", body: "{}" }); setJevStatus(result.available ? `Jev 连通成功 · ${result.latencyMs}ms` : `Jev 不可用 · ${result.error ?? "未知错误"}`); }}><Activity size={15} />测试 Jev 连接</button>
          {jevStatus && <div className="inline-status">{jevStatus}</div>}
        </Panel>
        <Panel title="防护强度">
          <div className="strength-list">{[
            ["low", "低", "概率 ≥ 50%", "更积极拦截"],
            ["medium", "中", "概率 ≥ 70%", "推荐默认"],
            ["high", "高", "概率 ≥ 85%", "减少误报"],
            ["extreme", "极高", "概率 ≥ 95%", "只拦截高置信度"],
            ["custom", "自定义", `概率 ≥ ${Math.round(settings.customThreshold * 100)}%`, "手动设置"]
          ].map(([value, label, threshold, note]) => <button key={value as string} className={`strength-row ${settings.strength === value ? "selected" : ""}`} onClick={() => setSettings({ ...settings, strength: value as Strength })}><span className="radio">{settings.strength === value && <span />}</span><span className="strength-copy"><strong>{label as string}</strong><small>{note as string}</small></span><span className="strength-threshold">{threshold as string}</span></button>)}</div>
          {settings.strength === "custom" && <label className="field-label custom-field">自定义阈值<input type="range" min="0" max="100" value={Math.round(settings.customThreshold * 100)} onChange={(event) => setSettings({ ...settings, customThreshold: Number(event.target.value) / 100 })} /><strong>{Math.round(settings.customThreshold * 100)}%</strong></label>}
          <div className="note-box"><span className="note-title">故障策略</span><p>AI 模式在 Jev 不可用时阻断；混合模式在传统规则通过后按传统结果降级放行，并记录事件。</p></div>
        </Panel>
      </div>
    </section>
  );
}

function PageHeading({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <div className="page-heading"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="muted">{description}</p></div>{action && <div>{action}</div>}</div>;
}

function Panel({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  return <section className="panel"><div className="panel-head"><h2>{title}</h2>{action}</div><div className="panel-body">{children}</div></section>;
}

function Metric({ label, value, detail, icon: Icon, accent = "default" }: { label: string; value: number; detail: string; icon: typeof Activity; accent?: string }) {
  return <div className={`metric ${accent}`}><div className="metric-top"><span>{label}</span><Icon size={16} /></div><strong>{value.toLocaleString()}</strong><small>{detail}</small></div>;
}

function DecisionPipeline({ mode }: { mode: Mode }) {
  return <div className="pipeline"><div className={`pipeline-step ${mode === "ai" ? "muted-step" : ""}`}><span>01</span><FileCode2 size={17} /><strong>传统规则</strong><small>{mode === "ai" ? "已跳过" : "检查路径、参数和请求体"}</small></div><ArrowRight className="pipeline-arrow" size={16} /><div className={`pipeline-step ${mode === "traditional" ? "muted-step" : ""}`}><span>02</span><Bot size={17} /><strong>Jev AI</strong><small>{mode === "traditional" ? "已跳过" : "返回 noul 恶意概率"}</small></div><ArrowRight className="pipeline-arrow" size={16} /><div className="pipeline-step final"><span>03</span><Shield size={17} /><strong>最终动作</strong><small>放行、拦截或降级</small></div></div>;
}

function EventList({ events }: { events: EventRecord[] }) {
  if (!events.length) return <div className="empty-state"><Activity size={22} /><span>还没有请求事件</span></div>;
  return <div className="event-list">{events.map((event) => <div className="event-row" key={event.id}><span className={`event-status ${event.action}`} /> <div className="event-copy"><strong>{event.path}</strong><span>{event.method} · {event.reason}</span></div><span className="event-score">{scoreLabel(event.score)}</span><span className="event-time">{formatTime(event.createdAt)}</span></div>)}</div>;
}

function EventTable({ events }: { events: EventRecord[] }) {
  if (!events.length) return <div className="empty-state"><Activity size={22} /><span>没有符合筛选条件的事件</span></div>;
  return <div className="table-wrap"><table><thead><tr><th>动作</th><th>请求</th><th>模式</th><th>Jev 概率</th><th>规则命中</th><th>时间</th></tr></thead><tbody>{events.map((event) => <tr key={event.id}><td><span className={`status-badge ${event.action === "allow" ? "green" : event.action === "block" ? "red" : "amber"}`}>{event.action === "allow" ? "放行" : event.action === "block" ? "拦截" : "错误"}</span></td><td><strong>{event.method} {event.path}</strong><small>{event.requestId.slice(0, 12)} · {event.ip ?? "unknown"}</small></td><td>{event.mode === "hybrid" ? "混合" : event.mode === "ai" ? "AI" : "规则"}</td><td>{scoreLabel(event.score)}{event.threshold !== undefined && <small> / {scoreLabel(event.threshold)}</small>}</td><td>{event.matchedRules.length ? event.matchedRules.map((rule) => rule.ruleId).join(", ") : "—"}</td><td>{formatTime(event.createdAt)}</td></tr>)}</tbody></table></div>;
}

function LoadingRows({ count }: { count: number }) {
  return <div className="loading-rows">{Array.from({ length: count }, (_, index) => <div className="skeleton-row" key={index}><span /><span /><span /></div>)}</div>;
}

function StatusLine({ icon: Icon, label, value, state }: { icon: typeof Server; label: string; value: string; state: "good" | "warn" }) {
  return <div className="status-line"><Icon size={16} /><span>{label}</span><strong>{value}</strong><span className={`status-dot ${state === "warn" ? "amber" : ""}`} /></div>;
}

export default App;
