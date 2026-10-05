import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { geoGraticule10, geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import worldAtlas from "world-atlas/countries-110m.json";
import type { GeometryCollection, Topology } from "topojson-specification";
import { PolicyFields, ScopedRules, initialPolicy, type SitePolicy, type ExceptionSeed } from "./PolicyControls";
import { PageFields, type PageConfig, type WaitRoomConfig } from "./PageFields";
import { IpFeedFields } from "./IpFeedFields";
import { NginxImport } from "./NginxImport";
import { GeoIpFields } from "./GeoIpFields";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Bot,
  Check,
  CircleGauge,
  Edit3,
  FileCode2,
  Filter,
  Globe2,
  LockKeyhole,
  LogOut,
  Map,
  Moon,
  Network,
  PanelLeft,
  Plus,
  Play,
  RefreshCw,
  Save,
  Search,
  Server,
  Shield,
  SlidersHorizontal,
  Sun,
  TerminalSquare,
  Trash2,
  Upload,
  X,
  Power
} from "lucide-react";

type Mode = "ai" | "traditional" | "hybrid";
type Strength = "veryLow" | "low" | "medium" | "high" | "extreme" | "custom";
type Theme = "dark" | "light";

type Settings = {
  mode: Mode;
  strength: Strength;
  customThreshold: number;
  model: string;
  jevBaseUrl: string;
  aiTimeoutMs: number;
  aiBodyLimit: number;
  upstreamUrl: string;
  apiKeyConfigured: boolean;
  apiKeySource: "environment" | "database" | "none";
  defaultPolicy: SitePolicy;
  auditMode: "sync" | "async";
  asyncBanBaseSeconds: number;
  asyncBanIncrementSeconds: number;
  asyncBanMaxSeconds: number;
  whitelistCidrs: string[];
  maliciousIpCidrs: string[];
  waitRoomDefaults: WaitRoomConfig;
  captcha: { enabled: boolean; provider: "local" | "turnstile" | "hcaptcha" | "recaptcha"; siteKey: string; secretConfigured: boolean; timeoutMs?: number; failureAction?: "allow" | "block"; trigger?: "always" | "cc" };
};

type AiProfile = { id: string; name: string; baseUrl: string; model: string; enabled: boolean; priority: number; timeoutMs: number; apiKeyConfigured: boolean; failureAction?: "inherit" | "allow" | "block" };

function useDialogFocus(open: boolean, onClose: () => void) {
  const ref = useRef<HTMLElement>(null);
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    ref.current?.querySelector<HTMLElement>("input:not(:disabled), select:not(:disabled), textarea:not(:disabled)")?.focus();
    const keydown = (event: KeyboardEvent) => {
      if (event.key === "Escape") { event.preventDefault(); close.current(); }
      if (event.key !== "Tab") return;
      const controls = Array.from(ref.current?.querySelectorAll<HTMLElement>("button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex='0']") ?? []).filter((element) => element.offsetParent !== null);
      const first = controls[0], last = controls.at(-1);
      if (!first || !last) return;
      if (!ref.current?.contains(document.activeElement) || event.shiftKey && document.activeElement === first || !event.shiftKey && document.activeElement === last) {
        event.preventDefault(); (event.shiftKey ? last : first).focus();
      }
    };
    document.addEventListener("keydown", keydown);
    return () => { document.removeEventListener("keydown", keydown); if (previous?.isConnected) previous.focus(); };
  }, [open]);
  return ref;
}

type Site = {
  id: string;
  name: string;
  listenPort: number;
  upstreamUrl: string;
  upstreamPool?: Array<{ url: string; weight?: number }>;
  redirect?: { statusCode: 301 | 302; location: string } | null;
  mode: Mode;
  enabled: boolean;
  createdAt: string;
  policy?: SitePolicy | null;
  operationMode?: "defense" | "record" | "maintenance";
  aiProfileId?: string | null;
  auditMode?: "sync" | "async" | null;
  captchaEnabled?: boolean | null;
  waitRoom?: WaitRoomConfig;
  maintenance?: PageConfig;
  upstreamError?: PageConfig;
  revision?: number;
  runtime?: { state: "pending" | "active" | "disabled" | "error"; desiredRevision: number; appliedRevision: number; lastError?: string };
};

type SiteDraft = Pick<Site, "name" | "listenPort" | "upstreamUrl" | "upstreamPool" | "redirect" | "mode" | "enabled" | "policy" | "operationMode" | "aiProfileId" | "auditMode" | "captchaEnabled" | "waitRoom" | "maintenance" | "upstreamError">;

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
  packageId?: string;
  license?: string;
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
  matchedRules: Array<{ ruleId: string; name: string; category: string; severity: string; target?: string; field?: string; snippet?: string }>;
  ai?: { model: string; noul: number; latencyMs: number; available: boolean; error?: string };
  partialInspection: boolean;
  country?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  asn?: number;
  createdAt: string;
  siteId?: string;
  listenPort?: number;
  policyRevision?: number;
  module?: string;
  localInspectionComplete?: boolean;
  aiInspectionComplete?: boolean;
  aiOmittedReason?: string;
  wouldBlock?: boolean;
  exceptionIds?: string[];
};

type MapData = {
  points: Array<{ latitude?: number; longitude?: number; country?: string; region?: string; city?: string; ip?: string; count: number }>;
  countries: Array<{ name: string; count: number }>;
  attackers: Array<{ ip?: string; count: number; path: string; rules: string[]; country?: string; region?: string; city?: string; asn?: number; lastSeen: string }>;
  blocked: number;
};

type TimeSeriesPoint = {
  time: string;
  total: number;
  allowed: number;
  blocked: number;
  errors: number;
};

type SystemStatus = {
  proxyPort: number;
  apiPort: number;
  sitePortRange: { min: number; max: number };
  maxRequestBodyBytes: number;
  httpsEnabled: boolean;
  httpsConfigured?: boolean;
  httpsPort?: number;
  geoIpAsnConfigured: boolean;
  ready?: boolean;
  aiRuntime?: { active: number; calls: number; limit: number; circuitOpen: boolean };
  events?: { queueDepth: number; queueLimit: number; droppedEvents: number; writeErrors: number; retentionDays: number };
};

type CountryProperties = { name?: string };
type WorldTopology = Topology<{ countries: GeometryCollection<CountryProperties> }>;
const worldFeatures = feature(
  worldAtlas as unknown as WorldTopology,
  (worldAtlas as unknown as WorldTopology).objects.countries
);
const worldGraticule = geoGraticule10();

const defaultSettings: Settings = {
  mode: "hybrid",
  strength: "medium",
  customThreshold: 0.5,
  model: "typesafe/jev-1.13",
  jevBaseUrl: "https://openrouter.ai",
  aiTimeoutMs: 2000,
  aiBodyLimit: 32768,
  upstreamUrl: "http://127.0.0.1:9000",
  apiKeyConfigured: false,
  apiKeySource: "none", defaultPolicy: initialPolicy,
  auditMode: "sync", asyncBanBaseSeconds: 60, asyncBanIncrementSeconds: 60, asyncBanMaxSeconds: 86400,
  whitelistCidrs: [], maliciousIpCidrs: [],
  waitRoomDefaults: { enabled: false, maxActive: 100, maxQueue: 100, timeoutSeconds: 60 },
  captcha: { enabled: false, provider: "local", siteKey: "", secretConfigured: false }
};

const defaultSystem: SystemStatus = {
  proxyPort: 8080,
  apiPort: 4000,
  sitePortRange: { min: 8080, max: 8099 },
  maxRequestBodyBytes: 10 * 1024 * 1024,
  httpsEnabled: false,
  geoIpAsnConfigured: false
};

const thresholds: Record<Exclude<Strength, "custom">, number> = {
  veryLow: 10,
  low: 30,
  medium: 50,
  high: 70,
  extreme: 90
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
    const payload = await response.json().catch(() => null) as { detail?: string } | null;
    throw new Error(payload?.detail ?? `HTTP ${response.status}`);
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
  const [setup, setSetup] = useState<boolean | null>(null);
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [loginError, setLoginError] = useState("");

  useEffect(() => {
    api<{ initialized: boolean }>("/api/v1/setup/status")
      .then((status) => {
        setSetup(status.initialized);
        if (status.initialized) {
          api("/api/v1/auth/me").then(() => setAuthenticated(true)).catch(() => setAuthenticated(false));
        } else {
          setAuthenticated(false);
        }
      })
      .catch(() => {
        setSetup(false);
        setAuthenticated(false);
      });
  }, []);

  if (setup === null || authenticated === null) {
    return <div className="boot-screen"><div className="boot-mark">J</div><span>正在连接控制平面</span></div>;
  }

  if (!setup) return <SetupScreen onComplete={() => { setSetup(true); setAuthenticated(false); }} />;
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
      onLogout={async () => {
        await api("/api/v1/auth/logout", { method: "POST" });
        setAuthenticated(false);
      }}
    />
  );
}

function SetupScreen({ onComplete }: { onComplete: () => void }) {
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  return (
    <main className="login-page">
      <div className="login-grid" />
      <section className="login-panel setup-panel">
        <BrandLockup />
        <div className="login-rule" />
        <p className="eyebrow">首次初始化</p>
        <h1>初始化防护控制台</h1>
        <p className="muted">先设置管理员密码即可进入控制台。Jev、模型、上游和 GeoIP 都可以稍后配置。</p>
        <form className="login-form" onSubmit={async (event) => {
          event.preventDefault();
          setError("");
          setSaving(true);
          try {
            await api("/api/v1/setup", { method: "POST", body: JSON.stringify({ password, confirmPassword }) });
            onComplete();
          } catch (setupError) {
            setError(setupError instanceof Error ? setupError.message : "初始化失败");
          } finally {
            setSaving(false);
          }
        }}>
          <label>管理员密码<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" minLength={8} required /></label>
          <label>确认管理员密码<input type="password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} autoComplete="new-password" minLength={8} required /></label>
          {error && <div className="form-error"><AlertTriangle size={15} />{error}</div>}
          <button className="primary-button full-width" type="submit" disabled={saving}><LockKeyhole size={16} />{saving ? "保存中" : "完成初始化"}</button>
        </form>
      </section>
    </main>
  );
}

function BrandLockup() {
  return <div className="brand-lockup"><div className="brand-glyph">J</div><div><strong>鉴流 · JianFlow WAF</strong><span>防护控制台</span></div></div>;
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
        <BrandLockup />
        <div className="login-rule" />
        <p className="eyebrow">本地管理员</p>
        <h1>登录控制台</h1>
        <p className="muted">管理流量入口、规则引擎、Jev 判断和攻击态势。</p>
        <form onSubmit={props.onSubmit} className="login-form">
          <label>管理员账号<input value={props.username} onChange={(event) => props.onUsername(event.target.value)} autoComplete="username" /></label>
          <label>管理员密码<input type="password" value={props.password} onChange={(event) => props.onPassword(event.target.value)} autoComplete="current-password" /></label>
          {props.error && <div className="form-error"><AlertTriangle size={15} />{props.error}</div>}
          <button className="primary-button full-width" type="submit"><LockKeyhole size={16} />进入控制台</button>
        </form>
        <div className="login-foot"><span>首次使用请完成初始化</span><span className="login-status"><span className="status-dot" />系统待命</span></div>
      </section>
    </main>
  );
}

function Console({ onLogout }: { onLogout: () => void }) {
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("jianflow-sidebar-collapsed") === "true");
  const [section, setSection] = useState("overview");
  const [dirtySections, setDirtySections] = useState<Record<string, boolean>>({});
  const [runtime, setRuntime] = useState<{ ready: boolean; apiPort: number; active: number } | null>(null);
  const [theme, setTheme] = useState<Theme>(() => (localStorage.getItem("jianflow-theme") as Theme | null) ?? "light");
  useEffect(() => { localStorage.setItem("jianflow-sidebar-collapsed", String(collapsed)); }, [collapsed]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("jianflow-theme", theme);
  }, [theme]);

  useEffect(() => {
    const refresh = async () => {
      try {
        const [system, result] = await Promise.all([api<SystemStatus & { ready: boolean }>("/api/v1/system"), api<{ data: Site[] }>("/api/v1/sites")]);
        setRuntime({ ready: system.ready, apiPort: system.apiPort, active: result.data.filter((site) => site.runtime?.state === "active").length });
      } catch { setRuntime(null); }
    };
    void refresh(); const timer = window.setInterval(() => void refresh(), 10000);
    return () => window.clearInterval(timer);
  }, [section]);

  const nav = [
    { id: "overview", label: "总览", icon: CircleGauge },
    { id: "map", label: "攻击大屏", icon: Map },
    { id: "events", label: "事件中心", icon: Activity },
    { id: "rules", label: "规则库", icon: FileCode2 },
    { id: "sites", label: "站点与上游", icon: Network },
    { id: "settings", label: "防护策略", icon: SlidersHorizontal }
  ];
  const navigate = (nextSection: string) => {
    if (nextSection === section) return;
    if (dirtySections[section] && !window.confirm("当前页面有未保存修改，确定离开吗？")) return;
    setSection(nextSection);
  };
  const setSitesDirty = useCallback((dirty: boolean) => {
    setDirtySections((current) => current.sites === dirty ? current : { ...current, sites: dirty });
  }, []);
  const setSettingsDirty = useCallback((dirty: boolean) => {
    setDirtySections((current) => current.settings === dirty ? current : { ...current, settings: dirty });
  }, []);
  return (
    <div className={`app-shell ${collapsed ? "sidebar-collapsed" : ""}`}>
      <aside className={`sidebar ${collapsed ? "collapsed" : ""}`}>
        <div className="sidebar-top"><div className="brand-glyph">J</div>{!collapsed && <div className="brand-copy"><strong>鉴流 · JianFlow</strong><span>防护控制台</span></div>}</div>
        <nav className="nav-list">
          {nav.map((item) => {
            const Icon = item.icon;
            return <button key={item.id} className={`nav-item ${section === item.id ? "active" : ""}`} onClick={() => navigate(item.id)} title={item.label} aria-label={item.label}><Icon size={17} />{!collapsed && <span>{item.label}</span>}</button>;
          })}
        </nav>
        <div className="sidebar-bottom">
          {!collapsed && <div className="node-card"><div className="node-card-head"><span className="node-status"><span className={`status-dot ${runtime?.ready ? "" : "amber"}`} />{runtime ? runtime.ready ? "入口已同步" : "入口待恢复" : "状态不可用"}</span><span>单节点</span></div><strong>{runtime ? `${runtime.active} 个运行入口` : "JianFlow WAF"}</strong><span>{runtime ? `API :${runtime.apiPort}` : "管理连接待恢复"}</span></div>}
          <button className="nav-item" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} title={theme === "dark" ? "切换浅色模式" : "切换深色模式"} aria-label={theme === "dark" ? "切换浅色模式" : "切换深色模式"}>{theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}{!collapsed && <span>{theme === "dark" ? "浅色模式" : "深色模式"}</span>}</button>
          <button className="nav-item" onClick={onLogout} title="退出登录"><LogOut size={17} />{!collapsed && <span>退出登录</span>}</button>
        </div>
      </aside>
      <main className="main-area">
        <header className="topbar">
          <button className="icon-button" onClick={() => setCollapsed(!collapsed)} aria-expanded={!collapsed} aria-label={collapsed ? "展开导航" : "折叠导航"} title={collapsed ? "展开导航" : "折叠导航"}><PanelLeft size={17} /></button>
          <div className="breadcrumb"><span>JianFlow WAF</span><ArrowRight size={13} /><strong>{navLabel(section)}</strong></div>
          <div className="topbar-right"><span className="live-pill"><span className={`status-dot ${runtime?.ready ? "" : "amber"}`} />{runtime ? `${runtime.active} 个运行入口` : "状态不可用"}</span><span className="topbar-time">{new Date().toLocaleDateString("zh-CN")}</span></div>
        </header>
        <div className="content">
          {section === "overview" && <Overview onSection={setSection} />}
          {section === "map" && <MapDashboard />}
          {section === "events" && <Events />}
          {section === "rules" && <Rules />}
          {section === "sites" && <Sites onDirtyChange={setSitesDirty} />}
          {section === "settings" && <SettingsPanel onDirtyChange={setSettingsDirty} />}
        </div>
      </main>
    </div>
  );
}

function navLabel(section: string): string {
  return { overview: "总览", map: "攻击大屏", events: "事件中心", rules: "规则库", sites: "站点与上游", settings: "防护策略" }[section] ?? "总览";
}

function useConsoleData() {
  const [settings, setSettings] = useState<Settings>(defaultSettings);
  const [summary, setSummary] = useState<Record<string, number>>({});
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [profiles, setProfiles] = useState<AiProfile[]>([]);
  const [mapData, setMapData] = useState<MapData>({ points: [], countries: [], attackers: [], blocked: 0 });
  const [timeseries, setTimeseries] = useState<TimeSeriesPoint[]>([]);
  const [system, setSystem] = useState<SystemStatus>(defaultSystem);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const refresh = async () => {
    setLoading(true);
    setError("");
    try {
      const [nextSettings, nextSummary, nextEvents, nextRules, nextMap, nextTimeseries, nextSystem] = await Promise.all([
        api<Settings>("/api/v1/settings"),
        api<Record<string, number>>("/api/v1/dashboard/summary"),
        api<{ data: EventRecord[] }>("/api/v1/events?limit=200"),
        api<{ data: Rule[] }>("/api/v1/rules"),
        api<MapData>("/api/v1/dashboard/attack-map?hours=24"),
        api<TimeSeriesPoint[]>("/api/v1/dashboard/timeseries?hours=24"),
        api<SystemStatus>("/api/v1/system")
      ]);
      setSettings(nextSettings);
      setSummary(nextSummary);
      setEvents(nextEvents.data);
      setRules(nextRules.data);
      setMapData(nextMap);
      setTimeseries(nextTimeseries);
      setSystem(nextSystem);
    } catch (refreshError) {
      setError(refreshError instanceof Error ? refreshError.message : "控制台数据加载失败");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void refresh(); }, []);
  return { settings, setSettings, summary, events, setEvents, rules, setRules, mapData, timeseries, system, error, loading, refresh };
}

function Overview({ onSection }: { onSection: (section: string) => void }) {
  const { settings, summary, events, mapData, timeseries, error, loading, refresh } = useConsoleData();
  const modeLabel = { ai: "AI 判断", traditional: "传统规则", hybrid: "混合模式" };
  return (
    <section>
      <PageHeading eyebrow="实时防护" title="防护总览" description="查看全量请求统计、当前策略和最近攻击态势。" action={<button className="secondary-button" onClick={() => void refresh()}><RefreshCw size={15} />刷新</button>} />
      {error && <ErrorNotice message={error} onRetry={() => void refresh()} />}
      <div className="signal-strip"><div><span className="signal-label">当前防护模式</span><strong>{modeLabel[settings.mode]}</strong></div><div><span className="signal-label">Jev 模型</span><strong>{settings.model}</strong></div><div><span className="signal-label">拦截阈值</span><strong>{thresholdLabel(settings)}</strong></div><div><span className="signal-label">AI 状态</span><strong className={settings.apiKeyConfigured ? "text-green" : "text-amber"}>{settings.apiKeyConfigured ? "已配置" : "未配置"}</strong></div></div>
      <div className="metric-grid">
        <Metric label="请求总计" value={summary.total ?? 0} detail="全量事件，不受列表分页影响" icon={Activity} />
        <Metric label="已拦截" value={summary.blocked ?? 0} detail="规则 + Jev 决策" icon={Shield} accent="red" />
        <Metric label="已放行" value={summary.allowed ?? 0} detail="低风险请求" icon={Check} accent="green" />
        <Metric label="错误事件" value={summary.errors ?? 0} detail="上游或 AI 故障" icon={AlertTriangle} accent="amber" />
      </div>
      <div className="two-column">
        <Panel title="攻击态势" action={<button className="text-button" onClick={() => onSection("map")}>进入大屏 <ArrowRight size={14} /></button>}>
          <MapPreview mapData={mapData} />
        </Panel>
        <Panel title="最近事件" action={<button className="text-button" onClick={() => onSection("events")}>查看事件 <ArrowRight size={14} /></button>}>
          {loading ? <LoadingRows count={5} /> : <EventList events={events.slice(0, 5)} />}
        </Panel>
      </div>
      <Panel title="24 小时流量趋势" action={<span className="panel-meta">按小时聚合 · 全量事件</span>}>
        <TrafficTrend points={timeseries} />
      </Panel>
    </section>
  );
}

function MapDashboard() {
  const { mapData, loading, error, refresh } = useConsoleData();
  const [mode, setMode] = useState<"2d" | "3d">("2d");
  return (
    <section>
      <PageHeading eyebrow="攻击来源" title="攻击大屏" description="按国家、地区和攻击 IP 聚合最近 24 小时的拦截事件。" action={<button className="secondary-button" onClick={() => void refresh()}><RefreshCw size={15} />刷新</button>} />
      {error && <ErrorNotice message={error} onRetry={() => void refresh()} />}
      <div className="map-toolbar"><div className="segmented"><button className={mode === "2d" ? "selected" : ""} onClick={() => setMode("2d")}><Map size={14} />2D</button><button className={mode === "3d" ? "selected" : ""} onClick={() => setMode("3d")}><Globe2 size={14} />3D</button></div><span className="panel-meta">最近 24 小时 · {mapData.blocked} 次拦截</span></div>
      <div className="map-layout">
        {mode === "2d" ? <Panel title="攻击来源地图"><AttackMap2D mapData={mapData} /></Panel> : <AttackGlobe mapData={mapData} />}
        <div className="stack-panels">
          <Panel title="来源排行"><CountryList countries={mapData.countries} loading={loading} /></Panel>
          <Panel title="高频攻击源"><AttackerList attackers={mapData.attackers} loading={loading} /></Panel>
        </div>
      </div>
    </section>
  );
}

function AttackMap2D({ mapData }: { mapData: MapData }) {
  const projection = geoNaturalEarth1().fitSize([960, 500], worldFeatures);
  const path = geoPath(projection);
  return <div className="map-stage map-2d">
    <svg className="map-svg" viewBox="0 0 960 500" role="img" aria-label="攻击来源世界地图">
      <path className="map-graticule" d={path(worldGraticule) ?? undefined} />
      <path className="map-land" d={path(worldFeatures) ?? undefined} />
      {mapData.points.map((point, index) => {
        if (point.latitude === undefined || point.longitude === undefined) return null;
        const projected = projection([point.longitude, point.latitude]);
        if (!projected) return null;
        const [x, y] = projected;
        return <g key={`${point.ip ?? "point"}-${index}`} className="map-point" transform={`translate(${x} ${y})`}>
          <title>{`${point.country ?? "未知地区"} · ${point.count} 次`}</title>
          <circle className="map-point-ring" r={Math.min(9, 3 + point.count / 20)} />
          <circle className="map-point-core" r={Math.min(4, 1.8 + point.count / 80)} />
        </g>;
      })}
    </svg>
    <div className="map-legend"><span><i className="legend-block" />拦截来源</span><span>离线 Natural Earth 国界 · 无 GeoIP 时显示未知地区</span></div>
  </div>;
}

function AttackGlobe({ mapData }: { mapData: MapData }) {
  const mountRef = useRef<HTMLDivElement>(null);
  const [fallback, setFallback] = useState(false);
  useEffect(() => {
    let disposed = false;
    let cleanup = () => undefined;
    setFallback(false);
    void import("three").then((THREE) => {
      if (disposed || !mountRef.current) return;
      const mount = mountRef.current;
      let renderer: InstanceType<typeof THREE.WebGLRenderer>;
      try {
        renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, preserveDrawingBuffer: true });
      } catch {
        if (!disposed) setFallback(true);
        return;
      }
      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(38, mount.clientWidth / Math.max(mount.clientHeight, 1), 0.1, 100);
      const fitDistance = () => 1.14 / Math.sin(Math.atan(Math.tan(camera.fov * Math.PI / 360) * Math.min(1, camera.aspect)));
      camera.position.z = fitDistance();
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
      renderer.setSize(mount.clientWidth, mount.clientHeight);
      mount.replaceChildren(renderer.domElement);
      const group = new THREE.Group();
      const globe = new THREE.Mesh(
        new THREE.SphereGeometry(1, 48, 32),
        new THREE.MeshBasicMaterial({ color: 0x758b94, wireframe: true, transparent: true, opacity: 0.2 })
      );
      group.add(globe);

      const borderVertices: number[] = [];
      const toPoint = (coordinate: unknown, radius: number): InstanceType<typeof THREE.Vector3> | undefined => {
        if (!Array.isArray(coordinate) || coordinate.length < 2
          || typeof coordinate[0] !== "number" || typeof coordinate[1] !== "number") return undefined;
        const lat = coordinate[1] * Math.PI / 180;
        const lon = -coordinate[0] * Math.PI / 180;
        return new THREE.Vector3(
          radius * Math.cos(lat) * Math.cos(lon),
          radius * Math.sin(lat),
          radius * Math.cos(lat) * Math.sin(lon)
        );
      };
      const addRing = (ring: unknown) => {
        if (!Array.isArray(ring)) return;
        const points = ring.map((coordinate) => toPoint(coordinate, 1.012)).filter(
          (point): point is InstanceType<typeof THREE.Vector3> => Boolean(point)
        );
        for (let index = 1; index < points.length; index += 1) {
          borderVertices.push(...points[index - 1]!.toArray(), ...points[index]!.toArray());
        }
      };
      for (const country of worldFeatures.features) {
        const geometry = country.geometry;
        if (geometry.type === "Polygon") geometry.coordinates.forEach(addRing);
        if (geometry.type === "MultiPolygon") geometry.coordinates.flat().forEach(addRing);
      }
      const borders = new THREE.LineSegments(
        new THREE.BufferGeometry().setAttribute("position", new THREE.Float32BufferAttribute(borderVertices, 3)),
        new THREE.LineBasicMaterial({ color: 0x258e72, transparent: true, opacity: 0.9 })
      );
      group.add(borders);

      const points = new THREE.Group();
      for (const point of mapData.points) {
        if (point.latitude === undefined || point.longitude === undefined) continue;
        const vector = toPoint([point.longitude, point.latitude], 1.045);
        if (!vector) continue;
        const marker = new THREE.Mesh(
          new THREE.SphereGeometry(0.018 + Math.min(point.count, 10) * 0.003, 8, 8),
          new THREE.MeshBasicMaterial({ color: 0xff675f })
        );
        marker.position.copy(vector);
        points.add(marker);
      }
      group.add(points);
      scene.add(group);
      let animation = 0;
      let dragging = false;
      let previousX = 0;
      let previousY = 0;
      const pointerDown = (event: PointerEvent) => {
        dragging = true;
        previousX = event.clientX;
        previousY = event.clientY;
        renderer.domElement.setPointerCapture(event.pointerId);
      };
      const pointerMove = (event: PointerEvent) => {
        if (!dragging) return;
        group.rotation.y += (event.clientX - previousX) * 0.008;
        group.rotation.x += (event.clientY - previousY) * 0.008;
        previousX = event.clientX;
        previousY = event.clientY;
      };
      const pointerUp = () => { dragging = false; };
      const wheel = (event: WheelEvent) => {
        event.preventDefault();
        camera.position.z = Math.min(fitDistance() * 1.5, Math.max(fitDistance() * 0.75, camera.position.z + event.deltaY * 0.0015));
      };
      const resize = () => {
        if (!mount.clientWidth || !mount.clientHeight) return;
        camera.aspect = mount.clientWidth / mount.clientHeight;
        camera.position.z = fitDistance();
        camera.updateProjectionMatrix();
        renderer.setSize(mount.clientWidth, mount.clientHeight);
      };
      const render = () => {
        if (!dragging) group.rotation.y += 0.0012;
        renderer.render(scene, camera);
        animation = window.requestAnimationFrame(render);
      };
      renderer.domElement.addEventListener("pointerdown", pointerDown);
      renderer.domElement.addEventListener("pointermove", pointerMove);
      renderer.domElement.addEventListener("pointerup", pointerUp);
      renderer.domElement.addEventListener("pointercancel", pointerUp);
      renderer.domElement.addEventListener("wheel", wheel, { passive: false });
      window.addEventListener("resize", resize);
      render();
      cleanup = () => {
        window.cancelAnimationFrame(animation);
        window.removeEventListener("resize", resize);
        renderer.domElement.removeEventListener("pointerdown", pointerDown);
        renderer.domElement.removeEventListener("pointermove", pointerMove);
        renderer.domElement.removeEventListener("pointerup", pointerUp);
        renderer.domElement.removeEventListener("pointercancel", pointerUp);
        renderer.domElement.removeEventListener("wheel", wheel);
        scene.traverse((object) => {
          const mesh = object as InstanceType<typeof THREE.Mesh>;
          if ("geometry" in mesh && mesh.geometry) mesh.geometry.dispose();
          if ("material" in mesh) {
            const material = mesh.material;
            if (Array.isArray(material)) material.forEach((item) => item.dispose());
            else material?.dispose();
          }
        });
        renderer.dispose();
        mount.replaceChildren();
      };
    }).catch(() => {
      if (!disposed) setFallback(true);
    });
    return () => {
      disposed = true;
      cleanup();
    };
  }, [mapData]);
  if (fallback) return <div className="map-fallback"><AttackMap2D mapData={mapData} /><span className="map-fallback-note">WebGL 不可用，已回退到 2D 地图</span></div>;
  return <div ref={mountRef} className="map-stage globe-stage" aria-label="攻击来源地球" />;
}

function MapPreview({ mapData }: { mapData: MapData }) {
  return <div className="map-preview"><AttackMap2D mapData={mapData} /><div className="map-preview-footer"><span>{mapData.points.length} 个已定位攻击点</span><span>{mapData.countries[0]?.name ?? "未知地区"} {mapData.countries[0] ? `· ${mapData.countries[0].count} 次` : ""}</span></div></div>;
}

function TrafficTrend({ points }: { points: TimeSeriesPoint[] }) {
  if (!points.length) return <div className="empty-state"><Activity size={22} /><span>暂时没有趋势数据</span></div>;
  const max = Math.max(...points.map((point) => point.total), 1);
  return <div className="trend-chart" aria-label="24 小时请求趋势">{points.map((point) => <div className="trend-column" key={point.time} title={`${formatTime(point.time)} · 总计 ${point.total} · 拦截 ${point.blocked} · 放行 ${point.allowed} · 错误 ${point.errors}`}><span className="trend-bar total" style={{ height: `${Math.max(point.total ? 8 : 2, point.total / max * 100)}%` }} /><span className="trend-bar blocked" style={{ height: `${Math.max(point.blocked ? 5 : 2, point.blocked / max * 100)}%` }} /></div>)}</div>;
}

function CountryList({ countries, loading }: { countries: MapData["countries"]; loading: boolean }) {
  if (loading) return <LoadingRows count={5} />;
  if (!countries.length) return <div className="empty-state"><Globe2 size={22} /><span>暂时没有带地区信息的拦截事件</span></div>;
  const max = countries[0]?.count ?? 1;
  return <div className="country-list">{countries.map((country) => <div className="country-row" key={country.name}><div><strong>{country.name}</strong><span>{country.count.toLocaleString()} 次拦截</span></div><div className="country-bar"><i style={{ width: `${Math.max(8, country.count / max * 100)}%` }} /></div></div>)}</div>;
}

function AttackerList({ attackers, loading }: { attackers: MapData["attackers"]; loading: boolean }) {
  if (loading) return <LoadingRows count={4} />;
  if (!attackers.length) return <div className="empty-state"><Shield size={22} /><span>暂时没有拦截攻击源</span></div>;
  return <div className="attacker-list">{attackers.slice(0, 8).map((attacker) => <div className="attacker-row" key={`${attacker.ip ?? "unknown"}-${attacker.path}`}>
    <div><strong>{attacker.ip ?? "未知 IP"}</strong><span>{attacker.country ?? "未知地区"}{attacker.asn ? ` · AS${attacker.asn}` : ""}</span></div>
    <div><b>{attacker.count.toLocaleString()}</b><small>{attacker.path}</small></div>
  </div>)}</div>;
}

function Events() {
  const [sites, setSites] = useState<Site[]>([]);
  const [siteId, setSiteId] = useState("");
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [selected, setSelected] = useState<EventRecord | null>(null);
  const refresh = async (append = false) => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({ limit: "50" });
      if (append && nextCursor) params.set("cursor", nextCursor);
      if (filter !== "all") params.set("action", filter);
      if (search.trim()) params.set("search", search.trim());
      if (since) params.set("since", new Date(since).toISOString());
      if (until) params.set("until", new Date(until).toISOString());
      if (siteId) params.set("siteId", siteId);
      const result = await api<{ data: EventRecord[]; nextCursor?: string }>(`/api/v1/events?${params}`);
      setEvents((current) => append ? [...current, ...result.data] : result.data);
      setNextCursor(result.nextCursor);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "事件加载失败");
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { void api<{ data: Site[] }>("/api/v1/sites").then((result) => setSites(result.data)).catch(() => {}); }, []);
  useEffect(() => { void refresh(); }, [filter, search, since, until, siteId]);
  return (
    <section>
      <PageHeading eyebrow="请求事件" title="事件中心" description="规则命中、AI 风险分数、来源与最终动作。" action={<button className="secondary-button" onClick={() => void refresh()}><RefreshCw size={15} />刷新</button>} />
      {error && <ErrorNotice message={error} onRetry={() => void refresh()} />}
      <label className="field-label event-site-filter">站点<select value={siteId} onChange={(event) => setSiteId(event.target.value)}><option value="">所有站点</option><option value="unknown">旧事件 / 未知入口</option>{sites.map((site) => <option value={site.id} key={site.id}>{site.name} · :{site.listenPort}</option>)}</select></label>
      <div className="toolbar event-filters"><div className="search-box"><Search size={16} /><input placeholder="搜索路径、request ID 或 IP" value={search} onChange={(event) => setSearch(event.target.value)} /></div><div className="segmented">{["all", "block", "allow", "error"].map((value) => <button key={value} className={filter === value ? "selected" : ""} onClick={() => setFilter(value)}>{value === "all" ? "全部" : value === "block" ? "已拦截" : value === "allow" ? "已放行" : "错误"}</button>)}</div><label className="date-filter">开始<input type="datetime-local" value={since} onChange={(event) => setSince(event.target.value)} /></label><label className="date-filter">结束<input type="datetime-local" value={until} onChange={(event) => setUntil(event.target.value)} /></label><button className="icon-button" title="清除筛选" onClick={() => { setSearch(""); setFilter("all"); setSince(""); setUntil(""); }}><X size={16} /></button></div>
      <Panel title={`${events.length} 条已加载事件`} action={<span className="panel-meta">服务端游标分页 · 统计为全量</span>}>
        {loading && !events.length ? <LoadingRows count={7} /> : <EventTable events={events} onSelect={setSelected} />}
      </Panel>
      {nextCursor && <button className="secondary-button load-more" disabled={loading} onClick={() => void refresh(true)}><ArrowRight size={15} />加载更多</button>}
      {selected && <EventDetails event={selected} onClose={() => setSelected(null)} />}
    </section>
  );
}

function Rules() {
  const { rules, error, loading, setRules, refresh } = useConsoleData();
  const [testPath, setTestPath] = useState("/search?q=union+select+password+from+users");
  const [testResult, setTestResult] = useState("");
  const [format, setFormat] = useState<"json" | "modsecurity">("json");
  const [importText, setImportText] = useState("");
  const [importStatus, setImportStatus] = useState("");
  const [preview, setPreview] = useState<{ valid: boolean; data: Rule[]; conflicts: string[]; errors: Array<{ message: string; line: number; column: number }> } | null>(null);
  const [conflict, setConflict] = useState<"reject" | "overwrite" | "skip">("reject");
  const [enabled, setEnabled] = useState(true);
  const toggleRule = async (rule: Rule) => {
    const updated = await api<Rule>(`/api/v1/rules/${rule.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !rule.enabled }) });
    setRules((current) => current.map((item) => item.id === updated.id ? updated : item));
  };
  return (
    <section>
      <PageHeading eyebrow="规则引擎" title="规则库" description="管理内置规则包、OWASP CRS 风格规则和用户导入规则。" action={<button className="secondary-button" onClick={() => void refresh()}><RefreshCw size={15} />刷新</button>} />
      {error && <ErrorNotice message={error} onRetry={() => void refresh()} />}
      <div className="two-column rules-layout">
        <Panel title="已加载规则" action={<span className="panel-meta">{rules.filter((rule) => rule.enabled).length} / {rules.length} 启用</span>}>
          {loading ? <LoadingRows count={6} /> : <div className="rule-list">{rules.map((rule) => <div className="rule-row" key={rule.id}><div className={`severity-mark ${rule.severity}`} /><div className="rule-main"><strong>{rule.name}</strong><span>{rule.id} · {rule.category}</span></div><span className="source-tag">{rule.source}</span><button className={`toggle ${rule.enabled ? "on" : ""}`} onClick={() => void toggleRule(rule)} aria-label={`切换 ${rule.name}`}><span /></button></div>)}</div>}
        </Panel>
        <div className="stack-panels">
          <Panel title="规则测试" action={<TerminalSquare size={16} className="panel-icon" />}>
            <label className="field-label">请求路径<input value={testPath} onChange={(event) => setTestPath(event.target.value)} /></label>
            <button className="primary-button" onClick={async () => { const url = new URL(testPath, "http://test.local"); const result = await api<{ matches: Rule[] }>("/api/v1/rules/test", { method: "POST", body: JSON.stringify({ method: "GET", path: url.pathname, query: url.search, headers: {} }) }); setTestResult(result.matches.length ? `命中 ${result.matches.length} 条规则：${result.matches.map((match) => match.name).join("、")}` : "未命中规则"); }}><Play size={15} />执行测试</button>
            {testResult && <div className={`test-result ${testResult.startsWith("未") ? "good" : "bad"}`}>{testResult.startsWith("未") ? <Check size={15} /> : <AlertTriangle size={15} />}{testResult}</div>}
          </Panel>
          <Panel title="导入规则" action={<Upload size={16} className="panel-icon" />}>
            <div className="inline-fields"><label className="field-label">格式<select value={format} onChange={(event) => { setFormat(event.target.value as "json" | "modsecurity"); setPreview(null); }}><option value="json">JSON</option><option value="modsecurity">ModSecurity SecRule</option></select></label><label className="file-button secondary-button"><Upload size={15} />选择文件<input type="file" accept={format === "json" ? ".json,application/json" : ".conf,.txt,text/plain"} onChange={async (event) => { const file = event.target.files?.[0]; if (file) { setImportText(await file.text()); setPreview(null); } }} /></label></div>
            <textarea className="rule-import-input" value={importText} onChange={(event) => setImportText(event.target.value)} placeholder={format === "json" ? '[{"id":"CUSTOM-001","name":"示例规则","target":"query","operator":"regex","pattern":"..."}]' : 'SecRule ARGS "@rx union\\\\s+select" "id:1001,deny"'} />
            <div className="import-actions"><button className="secondary-button" disabled={!importText.trim()} onClick={async () => { setImportStatus(""); const result = await api<{ valid: boolean; data: Rule[]; conflicts: string[]; errors: Array<{ message: string; line: number; column: number }> }>("/api/v1/rules/import/preview", { method: "POST", body: JSON.stringify({ format, content: importText }) }); setPreview(result); setImportStatus(result.valid ? `预览通过 · ${result.data.length} 条规则` : result.errors.map((item) => `${item.message}（行 ${item.line}，列 ${item.column}）`).join("；")); }}><Search size={15} />预览校验</button><label className="check-label"><input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />导入后启用</label>{preview?.conflicts.length ? <select value={conflict} onChange={(event) => setConflict(event.target.value as typeof conflict)}><option value="reject">冲突时报错</option><option value="overwrite">覆盖同 ID</option><option value="skip">跳过冲突</option></select> : null}</div>
            {preview?.valid && <div className="import-preview"><strong>待写入规则</strong>{preview.data.slice(0, 8).map((rule) => <div key={rule.id}><span className={`severity-mark ${rule.severity}`} /><span>{rule.id}</span><small>{rule.name} · {rule.target} · {rule.operator}</small></div>)}{preview.data.length > 8 && <small>还有 {preview.data.length - 8} 条规则</small>}</div>}
            <button className="primary-button" disabled={!preview?.valid} onClick={async () => { try { const result = await api<{ imported: number; skipped: number; warnings: string[] }>("/api/v1/rules/import", { method: "POST", body: JSON.stringify({ format, content: importText, conflict, enabled }) }); setImportStatus(`已导入 ${result.imported} 条，跳过 ${result.skipped} 条`); setImportText(""); setPreview(null); void refresh(); } catch (error) { setImportStatus(error instanceof Error ? error.message : "导入失败"); } }}><Upload size={15} />提交规则包</button>
            {importStatus && <div className="inline-status">{importStatus}</div>}
          </Panel>
        </div>
      </div>
    </section>
  );
}

function Sites({ onDirtyChange }: { onDirtyChange: (dirty: boolean) => void }) {
  const [scopedDirty, setScopedDirty] = useState(false);
  const [sites, setSites] = useState<Site[]>([]);
  const [settings, setSettings] = useState<Settings>(defaultSettings);
  const [system, setSystem] = useState<SystemStatus>(defaultSystem);
  const [form, setForm] = useState<SiteDraft | null>(null);
  const [originalForm, setOriginalForm] = useState<SiteDraft | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(true);
  const [rules, setRules] = useState<Rule[]>([]);
  const [profiles, setProfiles] = useState<AiProfile[]>([]);

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const [siteResult, nextSettings, nextSystem, ruleResult, profileResult] = await Promise.all([
        api<{ data: Site[] }>("/api/v1/sites"),
        api<Settings>("/api/v1/settings"),
        api<SystemStatus>("/api/v1/system"),
        api<{ data: Rule[] }>("/api/v1/rules"),
        api<{ data: AiProfile[] }>("/api/v1/ai-profiles")
      ]);
      setSites(siteResult.data);
      setSettings(nextSettings);
      setSystem(nextSystem);
      setRules(ruleResult.data);
      setProfiles(profileResult.data);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "站点加载失败");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, []);
  const formDirty = scopedDirty || Boolean(form && originalForm && JSON.stringify(form) !== JSON.stringify(originalForm));
  useEffect(() => {
    onDirtyChange(formDirty);
    const beforeUnload = (event: BeforeUnloadEvent) => {
      if (!formDirty) return;
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", beforeUnload);
    return () => {
      window.removeEventListener("beforeunload", beforeUnload);
      onDirtyChange(false);
    };
  }, [formDirty, onDirtyChange]);

  const availablePorts = (currentPort?: number) => Array.from(
    { length: system.sitePortRange.max - system.sitePortRange.min + 1 },
    (_, index) => system.sitePortRange.min + index
  ).filter((port) => port === currentPort || !sites.some((site) => site.listenPort === port));

  const openCreate = () => {
    const port = availablePorts()[0] ?? system.sitePortRange.min;
    const next: SiteDraft = {
      name: "",
      listenPort: port,
      upstreamUrl: settings.upstreamUrl,
      upstreamPool: [], redirect: null, auditMode: null, captchaEnabled: null,
      mode: settings.apiKeyConfigured ? settings.mode : "traditional",
      enabled: true, policy: null, operationMode: "defense", aiProfileId: profiles[0]?.id ?? null,
      waitRoom: structuredClone(settings.waitRoomDefaults), maintenance: { source: "default", statusCode: 503 }, upstreamError: { source: "default", statusCode: 502 }
    };
    setEditingId(null);
    setForm(next);
    setOriginalForm(next);
    setStatus("");
  };

  const openEdit = (site: Site) => {
    const next: SiteDraft = {
      name: site.name,
      listenPort: site.listenPort,
      upstreamUrl: site.upstreamUrl,
      upstreamPool: site.upstreamPool ?? [], redirect: site.redirect ?? null, auditMode: site.auditMode ?? null, captchaEnabled: site.captchaEnabled ?? null,
      mode: settings.apiKeyConfigured ? site.mode : "traditional",
      enabled: site.enabled, policy: site.policy ?? null, operationMode: site.operationMode ?? "defense", aiProfileId: site.aiProfileId ?? null,
      waitRoom: site.waitRoom ?? structuredClone(settings.waitRoomDefaults), maintenance: site.maintenance ?? { source: "default", statusCode: 503 }, upstreamError: site.upstreamError ?? { source: "default", statusCode: 502 }
    };
    setEditingId(site.id);
    setForm(next);
    setOriginalForm(next);
    setStatus("");
  };

  const closeEditor = () => {
    if (formDirty && !window.confirm("当前站点有未保存修改，确定取消吗？")) return;
    setForm(null);
    setOriginalForm(null);
    setEditingId(null);
  };

  const save = async () => {
    if (!form) return;
    setStatus("");
    try {
      const saved = await api<Site>(editingId ? `/api/v1/sites/${editingId}` : "/api/v1/sites", {
        method: editingId ? "PATCH" : "POST",
        body: JSON.stringify(form)
      });
      setSites((current) => editingId
        ? current.map((site) => site.id === saved.id ? saved : site)
        : [...current, saved]);
      setForm(null);
      setOriginalForm(null);
      setEditingId(null);
      setStatus("站点已保存");
    } catch (failure) {
      setStatus(failure instanceof Error ? failure.message : "站点保存失败");
    }
  };

  const toggle = async (site: Site) => {
    try {
      const updated = await api<Site>(`/api/v1/sites/${site.id}`, {
        method: "PATCH",
        body: JSON.stringify({ enabled: !site.enabled })
      });
      setSites((current) => current.map((entry) => entry.id === updated.id ? updated : entry));
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "站点状态更新失败");
    }
  };

  const remove = async (site: Site) => {
    if (site.id === "default") return;
    if (!window.confirm(`确定删除站点“${site.name}”吗？`)) return;
    try {
      await api(`/api/v1/sites/${site.id}`, { method: "DELETE" });
      setSites((current) => current.filter((entry) => entry.id !== site.id));
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "站点删除失败");
    }
  };

  return (
    <section>
      <PageHeading
        eyebrow="流量入口"
        title="站点与上游"
        description={`按入口端口管理受保护服务。可用端口范围 ${system.sitePortRange.min}-${system.sitePortRange.max}。`}
        action={<button className="primary-button" onClick={openCreate}><Plus size={15} />新建站点</button>}
      />
      {error && <ErrorNotice message={error} onRetry={() => void load()} />}
      {status && <div className="inline-status"><Check size={14} />{status}</div>}
      {loading ? <LoadingRows count={3} /> : <div className="site-grid">
        {sites.map((site) => (
          <article className={`site-card ${site.enabled ? "" : "disabled"}`} key={site.id}>
            <div className="site-card-head">
              <div>
                <span className="site-card-kicker">{site.id === "default" ? "默认入口" : "站点"}</span>
                <h2>{site.name}</h2>
              </div>
              <span className={`status-badge ${site.runtime?.state === "active" ? "green" : site.runtime?.state === "error" ? "red" : "amber"}`}>{site.runtime?.state === "active" ? "运行中" : site.runtime?.state === "error" ? "应用失败" : site.enabled ? "待应用" : "已停用"}</span>
            </div>
            <div className="site-card-data">
              <div><span>入口端口</span><strong>:{site.listenPort}</strong></div>
              <div><span>{site.redirect ? "跳转地址" : "上游地址"}</span><strong title={site.redirect?.location ?? site.upstreamUrl}>{site.redirect?.location ?? site.upstreamUrl}</strong></div>
              <div><span>转发方式</span><strong>{site.redirect ? `HTTP ${site.redirect.statusCode}` : site.upstreamPool?.length ? `加权轮询 · ${site.upstreamPool.length} 个节点` : "反向代理"}</strong></div>
              <div><span>运行模式</span><strong>{site.operationMode === "maintenance" ? "维护模式" : site.operationMode === "record" ? "记录模式" : "防御模式"}</strong></div>
              <div><span>审核模式</span><strong>{(site.auditMode ?? settings.auditMode) === "async" ? "异步审核" : "同步审核"}{!site.auditMode ? " · 继承全局" : ""}</strong></div>
              <div><span>防护模式</span><strong>{modeLabel(site.mode)}</strong></div>
              <div><span>策略</span><strong>{site.policy ? "本站覆盖" : "继承全局"} · {(site.policy ?? settings.defaultPolicy).enforcement === "observe" ? "观察" : "阻断"}</strong></div>
              <div><span>配置版本</span><strong>{site.runtime?.appliedRevision ?? 0} / {site.revision ?? 1}</strong></div>
            </div>
            {site.runtime?.lastError && <div className="runtime-error">{site.runtime.lastError}<button className="icon-button" title="重试应用" aria-label="重试应用" onClick={async () => { await api("/api/v1/listener-reloads", { method: "POST", body: "{}" }); void load(); }}><RefreshCw size={14} /></button></div>}
            <div className="site-card-actions">
              <button className="icon-button" title="编辑站点" aria-label="编辑站点" onClick={() => openEdit(site)}><Edit3 size={15} /></button>
              <button className="icon-button" title={site.enabled ? "停用站点" : "启用站点"} aria-label={site.enabled ? "停用站点" : "启用站点"} onClick={() => void toggle(site)}><Power size={15} /></button>
              <button className="icon-button danger-button" title={site.id === "default" ? "默认站点不可删除" : "删除站点"} aria-label="删除站点" disabled={site.id === "default"} onClick={() => void remove(site)}><Trash2 size={15} /></button>
            </div>
          </article>
        ))}
      </div>}
      <NginxImport request={api} onImported={() => void load()} />
      <div className="two-column sites-footer">
        <Panel title="数据面状态">
          <StatusLine icon={Server} label="配置端口范围" value={`:${system.sitePortRange.min}-${system.sitePortRange.max}`} state="good" />
          <StatusLine icon={Network} label="实际运行入口" value={`${sites.filter((site) => site.runtime?.state === "active").length} / ${sites.filter((site) => site.enabled).length} 个站点`} state={system.ready ? "good" : "warn"} />
          <StatusLine icon={Globe2} label="HTTPS 终止" value={system.httpsEnabled ? `:${system.httpsPort}` : system.httpsConfigured ? "未运行" : "未配置证书"} state={system.httpsEnabled ? "good" : "warn"} />
        </Panel>
        <Panel title="资源状态">
          <StatusLine icon={Bot} label="AI 并发 / 分钟调用" value={`${system.aiRuntime?.active ?? 0} / ${system.aiRuntime?.calls ?? 0}`} state={system.aiRuntime?.circuitOpen ? "warn" : "good"} />
          <StatusLine icon={Activity} label="事件待写 / 丢弃" value={`${system.events?.queueDepth ?? 0} / ${system.events?.droppedEvents ?? 0}`} state={system.events?.droppedEvents ? "warn" : "good"} />
          <StatusLine icon={AlertTriangle} label="事件写入错误" value={String(system.events?.writeErrors ?? 0)} state={system.events?.writeErrors ? "warn" : "good"} />
        </Panel>
      </div>
      {form && <SiteEditor
        form={form}
        editingId={editingId}
        hasJevKey={settings.apiKeyConfigured}
        globalPolicy={settings.defaultPolicy}
        rules={rules}
        onScopedDirtyChange={setScopedDirty}
        profiles={profiles}
        ports={editingId === "default" ? [system.proxyPort] : availablePorts(form.listenPort)}
        onChange={(patch) => setForm((current) => current ? { ...current, ...patch } : current)}
        onSave={() => void save()}
        onCancel={closeEditor}
        status={status}
      />}
    </section>
  );
}

function SiteEditor(props: {
  form: SiteDraft;
  editingId: string | null;
  hasJevKey: boolean;
  ports: number[];
  onChange: (patch: Partial<SiteDraft>) => void;
  onSave: () => void;
  onCancel: () => void;
  status: string;
  globalPolicy: SitePolicy;
  rules: Rule[];
  profiles: AiProfile[];
  onScopedDirtyChange: (dirty: boolean) => void;
}) {
  const [tab, setTab] = useState("入口");
  const dialogRef = useDialogFocus(true, props.onCancel);
  const canUseAi = props.form.aiProfileId ? props.profiles.some((profile) => profile.id === props.form.aiProfileId && profile.enabled && profile.apiKeyConfigured) : props.hasJevKey;
  const [scopedDrafts, setScopedDrafts] = useState({ exceptions: false, access: false });
  const exceptionsDirty = useCallback((dirty: boolean) => setScopedDrafts((current) => current.exceptions === dirty ? current : { ...current, exceptions: dirty }), []);
  const accessDirty = useCallback((dirty: boolean) => setScopedDrafts((current) => current.access === dirty ? current : { ...current, access: dirty }), []);
  useEffect(() => { props.onScopedDirtyChange(scopedDrafts.exceptions || scopedDrafts.access); }, [scopedDrafts, props.onScopedDirtyChange]);
  const switchTab = (next: string) => {
    if (next === tab) return;
    if ((scopedDrafts.exceptions || scopedDrafts.access) && !window.confirm("有未保存配置，确定切换吗？")) return;
    setTab(next);
  };
  const [siteEvents, setSiteEvents] = useState<EventRecord[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<EventRecord | null>(null);
  useEffect(() => {
    if (tab === "事件" && props.editingId) void api<{ data: EventRecord[] }>(`/api/v1/events?siteId=${props.editingId}&limit=50`).then((result) => setSiteEvents(result.data));
  }, [tab, props.editingId]);
  return <div className="modal-backdrop site-editor-backdrop" role="presentation" onClick={(event) => { if (event.target === event.currentTarget) props.onCancel(); }}>
    <section ref={dialogRef} className="site-editor" role="dialog" aria-modal="true" aria-label={props.editingId ? "编辑站点" : "新建站点"}>
      <div className="drawer-head"><div><p className="eyebrow">站点配置</p><h2>{props.editingId ? "编辑站点" : "新建站点"}</h2></div><button className="icon-button" title="关闭" aria-label="关闭" onClick={props.onCancel}><X size={16} /></button></div>
      <div className="site-tabs" role="tablist">{["入口", "防护", "限速", "页面", "例外", "事件"].map((value) => <button type="button" role="tab" aria-selected={tab === value} disabled={!props.editingId && ["例外", "事件"].includes(value)} className={tab === value ? "selected" : ""} key={value} onClick={() => switchTab(value)}>{value}</button>)}</div>
      <div className="site-editor-body">
        {tab === "入口" && <>
        <label className="field-label">站点名称<input value={props.form.name} onChange={(event) => props.onChange({ name: event.target.value })} /></label>
        <label className="field-label">入口端口<select value={props.form.listenPort} onChange={(event) => props.onChange({ listenPort: Number(event.target.value) })}>{props.ports.map((port) => <option key={port} value={port}>:{port}</option>)}</select></label>
        <label className="field-label">转发方式<select value={props.form.redirect?.statusCode ?? "proxy"} onChange={(event) => props.onChange({ redirect: event.target.value === "proxy" ? null : { statusCode: Number(event.target.value) as 301 | 302, location: props.form.redirect?.location ?? props.form.upstreamUrl } })}><option value="proxy">反向代理</option><option value="301">301 永久跳转</option><option value="302">302 临时跳转</option></select></label>
        {props.form.redirect ? <label className="field-label">跳转地址<input type="url" value={props.form.redirect.location} onChange={(event) => props.onChange({ redirect: { ...props.form.redirect!, location: event.target.value } })} /></label> : <>
          <label className="field-label">默认上游地址<input value={props.form.upstreamUrl} onChange={(event) => props.onChange({ upstreamUrl: event.target.value })} placeholder="http://app:9000" /></label>
          <div className="upstream-pool-fields">
            <div className="scoped-heading"><h3>上游池 · 加权轮询</h3><button type="button" className="icon-button" title="添加上游节点" aria-label="添加上游节点" disabled={(props.form.upstreamPool?.length ?? 0) >= 32} onClick={() => props.onChange({ upstreamPool: [...(props.form.upstreamPool ?? []), { url: "", weight: 1 }] })}><Plus size={16} /></button></div>
            {(props.form.upstreamPool ?? []).map((node, index) => <div className="upstream-node-row" key={index}>
              <label className="field-label">节点 {index + 1}<input type="url" value={node.url} maxLength={2048} onChange={(event) => props.onChange({ upstreamPool: props.form.upstreamPool!.map((entry, position) => position === index ? { ...entry, url: event.target.value } : entry) })} placeholder="http://app:9000" /></label>
              <label className="field-label">权重<input type="number" min={1} max={1000} step={1} value={node.weight ?? 1} onChange={(event) => props.onChange({ upstreamPool: props.form.upstreamPool!.map((entry, position) => position === index ? { ...entry, weight: Number(event.target.value) } : entry) })} /></label>
              <button type="button" className="icon-button danger-button" title={`删除节点 ${index + 1}`} aria-label={`删除节点 ${index + 1}`} onClick={() => props.onChange({ upstreamPool: props.form.upstreamPool!.filter((_, position) => position !== index) })}><Trash2 size={15} /></button>
            </div>)}
          </div>
        </>}
        <label className="field-label">防护模式<select value={props.form.mode} onChange={(event) => props.onChange({ mode: event.target.value as Mode })}><option value="traditional">传统规则</option><option value="hybrid" disabled={!canUseAi}>混合模式{!canUseAi ? "（需配置 Jev key）" : ""}</option><option value="ai" disabled={!canUseAi}>AI 判断{!canUseAi ? "（需配置 Jev key）" : ""}</option></select></label>
        <label className="field-label">运行模式<select value={props.form.operationMode ?? "defense"} onChange={(event) => props.onChange({ operationMode: event.target.value as "defense" | "record" | "maintenance" })}><option value="defense">防御模式</option><option value="record">记录模式</option><option value="maintenance">维护模式</option></select></label>
        <label className="field-label">API Profile<select value={props.form.aiProfileId ?? ""} onChange={(event) => props.onChange({ aiProfileId: event.target.value || null })}><option value="">自动选择</option>{props.profiles.map((profile) => <option key={profile.id} value={profile.id} disabled={!profile.apiKeyConfigured || !profile.enabled}>{profile.name}{profile.apiKeyConfigured ? "" : "（无 Key）"}</option>)}</select></label>
        <label className="field-label">审核模式<select value={props.form.auditMode ?? ""} onChange={(event) => props.onChange({ auditMode: event.target.value ? event.target.value as "sync" | "async" : null })}><option value="">继承全局</option><option value="sync">同步审核</option><option value="async">异步审核</option></select></label>
        <label className="field-label">人机验证<select value={props.form.captchaEnabled === null || props.form.captchaEnabled === undefined ? "inherit" : props.form.captchaEnabled ? "on" : "off"} onChange={(event) => props.onChange({ captchaEnabled: event.target.value === "inherit" ? null : event.target.value === "on" })}><option value="inherit">继承全局</option><option value="on">启用</option><option value="off">停用</option></select></label>
        <label className="check-label"><input type="checkbox" checked={props.form.waitRoom?.enabled ?? false} onChange={(event) => props.onChange({ waitRoom: { ...(props.form.waitRoom ?? { maxActive: 100, maxQueue: 100, timeoutSeconds: 60 }), enabled: event.target.checked } })} />启用等候室</label>
        <div className="form-grid compact-grid"><label className="field-label">活动上限<input type="number" value={props.form.waitRoom?.maxActive ?? 100} onChange={(event) => props.onChange({ waitRoom: { ...(props.form.waitRoom ?? { enabled: false, maxActive: 100, maxQueue: 100, timeoutSeconds: 60 }), maxActive: Number(event.target.value) } })} /></label><label className="field-label">队列上限<input type="number" value={props.form.waitRoom?.maxQueue ?? 100} onChange={(event) => props.onChange({ waitRoom: { ...(props.form.waitRoom ?? { enabled: false, maxActive: 100, maxQueue: 100, timeoutSeconds: 60 }), maxQueue: Number(event.target.value) } })} /></label><label className="field-label">等待超时<input type="number" value={props.form.waitRoom?.timeoutSeconds ?? 60} onChange={(event) => props.onChange({ waitRoom: { ...(props.form.waitRoom ?? { enabled: false, maxActive: 100, maxQueue: 100, timeoutSeconds: 60 }), timeoutSeconds: Number(event.target.value) } })} /></label></div>
        <label className="check-label site-enabled"><input type="checkbox" checked={props.form.enabled} onChange={(event) => props.onChange({ enabled: event.target.checked })} />启用此入口</label>
        {!canUseAi && <div className="inline-status">所选 Profile 未启用或未配置 Key，保存时会使用传统规则。</div>}
        </>}
        {["防护", "限速"].includes(tab) && <><label className="check-label"><input type="checkbox" checked={!props.form.policy} onChange={(event) => props.onChange({ policy: event.target.checked ? null : structuredClone(props.globalPolicy) })} />继承全局默认策略</label>
          <PolicyFields policy={props.form.policy ?? props.globalPolicy} disabled={!props.form.policy} rateOnly={tab === "限速"} rules={props.rules} onChange={(policy) => props.onChange({ policy })} /></>}
        {tab === "页面" && <>
          <PageFields title="维护页面" page={props.form.maintenance ?? { source: "default", statusCode: 503 }} onChange={(maintenance) => props.onChange({ maintenance })} />
          <PageFields title="上游错误页面" page={props.form.upstreamError ?? { source: "default", statusCode: 502 }} onChange={(upstreamError) => props.onChange({ upstreamError })} />
          <PageFields title="等候室页面" page={props.form.waitRoom?.page ?? { source: "default", statusCode: 429 }} onChange={(page) => props.onChange({ waitRoom: { ...(props.form.waitRoom ?? { enabled: false, maxActive: 100, maxQueue: 100, timeoutSeconds: 60 }), page } })} />
          <label className="field-label">队列满时<select value={props.form.waitRoom?.fullAction ?? "reject"} onChange={(event) => props.onChange({ waitRoom: { ...(props.form.waitRoom ?? { enabled: false, maxActive: 100, maxQueue: 100, timeoutSeconds: 60 }), fullAction: event.target.value as "reject" | "unavailable" } })}><option value="reject">429 请求过多</option><option value="unavailable">503 暂不可用</option></select></label>
        </>}
        {tab === "例外" && props.editingId && <><ScopedRules api={api} siteId={props.editingId} kind="exceptions" rules={props.rules} onDirtyChange={exceptionsDirty} /><div className="divider" /><ScopedRules api={api} siteId={props.editingId} kind="access-rules" rules={props.rules} onDirtyChange={accessDirty} /></>}
        {tab === "事件" && <EventTable events={siteEvents} onSelect={setSelectedEvent} />}
      </div>
      {props.status && <div className="form-error"><AlertTriangle size={15} />{props.status}</div>}
      <div className="site-editor-actions"><button className="secondary-button" onClick={props.onCancel}>取消</button>{!["例外", "事件"].includes(tab) && <button className="primary-button" onClick={props.onSave}><Save size={15} />保存站点</button>}</div>
      {selectedEvent && <EventDetails event={selectedEvent} onClose={() => setSelectedEvent(null)} />}
    </section>
  </div>;
}

function SettingsPanel({ onDirtyChange }: { onDirtyChange: (dirty: boolean) => void }) {
  const [rules, setRules] = useState<Rule[]>([]);
  const [serverSettings, setServerSettings] = useState<Settings | null>(null);
  const [draft, setDraft] = useState<Settings>(defaultSettings);
  const [apiKey, setApiKey] = useState("");
  const [clearApiKey, setClearApiKey] = useState(false);
  const [captchaSecret, setCaptchaSecret] = useState("");
  const [clearCaptchaSecret, setClearCaptchaSecret] = useState(false);
  const [jevStatus, setJevStatus] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [profiles, setProfiles] = useState<AiProfile[]>([]);
  const [profileDraft, setProfileDraft] = useState<{ id?: string; name: string; baseUrl: string; model: string; apiKey: string; enabled: boolean; priority: number; timeoutMs: number; failureAction?: "inherit" | "allow" | "block"; clearKey?: boolean } | null>(null);
  const [profileError, setProfileError] = useState("");
  const profileDialogRef = useDialogFocus(Boolean(profileDraft), () => { setProfileDraft(null); setProfileError(""); });

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const [next, ruleResult, profileResult] = await Promise.all([api<Settings>("/api/v1/settings"), api<{ data: Rule[] }>("/api/v1/rules"), api<{ data: AiProfile[] }>("/api/v1/ai-profiles")]);
      setRules(ruleResult.data);
      setProfiles(profileResult.data);
      setServerSettings(next);
      setDraft(next);
      setApiKey("");
      setClearApiKey(false);
      setCaptchaSecret(""); setClearCaptchaSecret(false);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "策略加载失败");
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { void load(); }, []);
  const dirty = Boolean(serverSettings && (
    JSON.stringify(draft) !== JSON.stringify(serverSettings) || apiKey.trim() || clearApiKey || profileDraft || captchaSecret.trim() || clearCaptchaSecret
  ));
  useEffect(() => {
    onDirtyChange(dirty);
    const beforeUnload = (event: BeforeUnloadEvent) => {
      if (!dirty) return;
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", beforeUnload);
    return () => {
      window.removeEventListener("beforeunload", beforeUnload);
      onDirtyChange(false);
    };
  }, [dirty, onDirtyChange]);

  const hasJevKey = draft.apiKeyConfigured && !clearApiKey || Boolean(apiKey.trim()) || profiles.some((profile) => profile.id !== "default" && profile.enabled && profile.apiKeyConfigured);
  useEffect(() => {
    if (!hasJevKey) {
      setDraft((current) => current.mode === "traditional" ? current : { ...current, mode: "traditional" });
    }
  }, [hasJevKey]);
  const updateDraft = (patch: Partial<Settings>) => setDraft((current) => ({ ...current, ...patch,
    defaultPolicy: patch.defaultPolicy ?? { ...current.defaultPolicy,
      strength: patch.strength ?? current.strength, customThreshold: patch.customThreshold ?? current.customThreshold }
  }));
  const cancel = () => {
    if (serverSettings) setDraft(serverSettings);
    setApiKey("");
    setClearApiKey(false);
    setCaptchaSecret(""); setClearCaptchaSecret(false);
    setJevStatus("");
  };
  const save = async () => {
    const { apiKeyConfigured: _configured, apiKeySource: _source, ...editable } = draft;
    try {
      const body = {
        ...editable,
        captcha: { ...draft.captcha, ...(clearCaptchaSecret ? { secret: null } : captchaSecret.trim() ? { secret: captchaSecret.trim() } : {}) },
        ...(clearApiKey ? { apiKey: null } : apiKey.trim() ? { apiKey: apiKey.trim() } : {})
      };
      const next = await api<Settings>("/api/v1/settings", { method: "PATCH", body: JSON.stringify(body) });
      setServerSettings(next);
      setDraft(next);
      setApiKey("");
      setClearApiKey(false);
      setCaptchaSecret(""); setClearCaptchaSecret(false);
      setJevStatus("策略已保存");
    } catch (failure) {
      setJevStatus(failure instanceof Error ? failure.message : "策略保存失败");
    }
  };
  const saveProfile = async () => {
    if (!profileDraft) return;
    try {
      const payload = { name: profileDraft.name, baseUrl: profileDraft.baseUrl, model: profileDraft.model, enabled: profileDraft.enabled, priority: profileDraft.priority, timeoutMs: profileDraft.timeoutMs, failureAction: profileDraft.failureAction ?? "inherit", ...(profileDraft.clearKey ? { apiKey: null } : profileDraft.apiKey.trim() ? { apiKey: profileDraft.apiKey.trim() } : {}) };
      await api<AiProfile>(profileDraft.id ? `/api/v1/ai-profiles/${profileDraft.id}` : "/api/v1/ai-profiles", { method: profileDraft.id ? "PATCH" : "POST", body: JSON.stringify(payload) });
      await refreshProfiles();
      setProfileDraft(null); setProfileError("");
    } catch (failure) { setProfileError(failure instanceof Error ? failure.message : "Profile 保存失败"); }
  };
  const refreshProfiles = async () => {
    const [list, next] = await Promise.all([api<{ data: AiProfile[] }>("/api/v1/ai-profiles"), api<Settings>("/api/v1/settings")]);
    setProfiles(list.data);
    setDraft((current) => ({ ...current, apiKeyConfigured: next.apiKeyConfigured, apiKeySource: next.apiKeySource,
      jevBaseUrl: current.jevBaseUrl === serverSettings?.jevBaseUrl ? next.jevBaseUrl : current.jevBaseUrl,
      model: current.model === serverSettings?.model ? next.model : current.model,
      aiTimeoutMs: current.aiTimeoutMs === serverSettings?.aiTimeoutMs ? next.aiTimeoutMs : current.aiTimeoutMs,
    }));
    setServerSettings(next);
  };
  const modeOptions: Array<[Mode, string, string, typeof Network]> = [
    ["hybrid", "混合模式", "先规则过滤，再由 Jev 复核", Network],
    ["ai", "AI 判断", "由 Jev 判断请求风险分数", Bot],
    ["traditional", "传统规则", "仅使用本地规则引擎", FileCode2]
  ];
  const strengthOptions: Array<[Strength, string, string, string]> = [
    ["veryLow", "10%", "分数 ≥ 10%", "较低阈值，拦截范围更广"],
    ["low", "30%", "分数 ≥ 30%", "较低阈值"],
    ["medium", "50%", "分数 ≥ 50%", "默认阈值"],
    ["high", "70%", "分数 ≥ 70%", "较高阈值"],
    ["extreme", "90%", "分数 ≥ 90%", "较高阈值，拦截范围更窄"],
    ["custom", "自定义", `分数 ≥ ${Math.round(draft.customThreshold * 100)}%`, "手动设置"]
  ];
  return (
    <section>
      <PageHeading
        eyebrow="防护策略"
        title="防护策略"
        description="全局默认策略与 Jev 配置。"
        action={<div className="panel-actions"><span className={`draft-state ${dirty ? "dirty" : ""}`}>{dirty ? "有未保存修改" : "已同步"}</span><button className="secondary-button" disabled={!dirty || loading} onClick={cancel}>取消更改</button><button className="primary-button" disabled={!dirty || loading} onClick={() => void save()}><Save size={15} />保存策略</button></div>}
      />
      {error && <ErrorNotice message={error} onRetry={() => void load()} />}
      <div className="two-column settings-layout">
        <Panel title="防护模式">
          <div className="mode-options">{modeOptions.map(([value, label, detail, Icon]) => {
            const disabled = value !== "traditional" && !hasJevKey;
            return <button key={value} type="button" disabled={disabled} className={`mode-option ${draft.mode === value ? "selected" : ""} ${disabled ? "disabled-option" : ""}`} onClick={() => updateDraft({ mode: value })}><span className="mode-option-icon"><Icon size={17} /></span><span><strong>{label}</strong><small>{detail}{disabled ? " · 需配置 Jev key" : ""}</small></span>{draft.mode === value && <Check size={16} className="check-icon" />}</button>;
          })}</div>
          <div className="divider" />
          <label className="field-label">Jev baseURL<input value={draft.jevBaseUrl} onChange={(event) => updateDraft({ jevBaseUrl: event.target.value })} placeholder="https://openrouter.ai 或完整决策地址" /></label>
          <label className="field-label">Jev 模型<input value={draft.model} onChange={(event) => updateDraft({ model: event.target.value })} /></label>
          <label className="field-label">API key<input type="password" value={apiKey} onChange={(event) => { setApiKey(event.target.value); setClearApiKey(false); }} placeholder={draft.apiKeyConfigured ? "已配置，输入新 key 可替换" : "可选，不影响首次初始化"} autoComplete="new-password" /></label>
          <div className="api-state"><span className={`status-dot ${hasJevKey ? "" : "amber"}`} /><span>{hasJevKey ? `Jev key 已配置 · ${draft.apiKeySource === "environment" ? ".env" : "WebUI"}` : "Jev key 未配置"}</span><span className="panel-meta">服务端加密保存，不回显</span></div>
          <div className="form-grid compact-grid">
            <label className="field-label">AI 超时（毫秒）<input type="number" min="100" max="60000" value={draft.aiTimeoutMs} onChange={(event) => updateDraft({ aiTimeoutMs: Number(event.target.value) })} /></label>
            <label className="field-label">AI 正文上限（字节）<input type="number" min="1024" value={draft.aiBodyLimit} onChange={(event) => updateDraft({ aiBodyLimit: Number(event.target.value) })} /></label>
          </div>
          <div className="settings-actions"><button className="secondary-button" disabled={dirty} onClick={async () => { try { const result = await api<{ available: boolean; error?: string; latencyMs: number }>("/api/v1/settings/test-jev", { method: "POST", body: "{}" }); setJevStatus(result.available ? `Jev 连通成功 · ${result.latencyMs}ms` : `Jev 不可用 · ${result.error ?? "未知错误"}`); } catch (failure) { setJevStatus(failure instanceof Error ? failure.message : "Jev 测试失败"); } }}><Activity size={15} />测试 Jev 连接</button>{draft.apiKeySource === "database" && <button className="text-button" onClick={() => { setClearApiKey(true); setApiKey(""); setJevStatus("已标记移除 WebUI key，点击保存后生效"); }}><X size={14} />移除 WebUI key</button>}</div>
          {jevStatus && <div className="inline-status">{jevStatus}</div>}
        </Panel>
        <Panel title="AI 拦截阈值">
          <div className="strength-list">{strengthOptions.map(([value, label, threshold, note]) => <button key={value} type="button" className={`strength-row ${draft.strength === value ? "selected" : ""}`} onClick={() => updateDraft({ strength: value })}><span className="radio">{draft.strength === value && <span />}</span><span className="strength-copy"><strong>{label}</strong><small>{note}</small></span><span className="strength-threshold">{threshold}</span></button>)}</div>
          {draft.strength === "custom" && <label className="field-label custom-field">自定义阈值<input type="range" min="0" max="100" value={Math.round(draft.customThreshold * 100)} onChange={(event) => updateDraft({ customThreshold: Number(event.target.value) / 100 })} /><strong>{Math.round(draft.customThreshold * 100)}%</strong></label>}
          <div className="note-box"><span className="note-title">当前 AI 故障策略</span><p>{draft.defaultPolicy.aiFailureAction === "block" ? "拒绝请求" : draft.defaultPolicy.aiFailureAction === "allow" ? "继续本地结果" : "按模式降级：AI 拒绝，混合继续本地结果"}</p></div>
        </Panel>
      </div>
      <div className="two-column settings-layout global-policy-layout"><Panel title="全局默认防护"><PolicyFields policy={draft.defaultPolicy} rules={rules} onChange={(policy) => updateDraft({ defaultPolicy: policy, strength: policy.strength, customThreshold: policy.customThreshold })} /></Panel><Panel title="全局默认限速"><PolicyFields policy={draft.defaultPolicy} rateOnly onChange={(policy) => updateDraft({ defaultPolicy: policy })} /></Panel></div>
      <div className="two-column settings-layout">
        <Panel title="Jev / API Profiles" action={<button className="secondary-button" onClick={() => setProfileDraft({ name: "", baseUrl: draft.jevBaseUrl, model: draft.model, apiKey: "", enabled: true, priority: 100, timeoutMs: draft.aiTimeoutMs })}><Plus size={14} />新增 Profile</button>}>
          <div className="profile-list">{profiles.length ? profiles.map((profile) => <div className="profile-row" key={profile.id}><div><strong>{profile.name}</strong><span>{profile.model} · {profile.baseUrl}</span></div><span className={`status-badge ${profile.apiKeyConfigured && profile.enabled ? "green" : "amber"}`}>{!profile.enabled ? "已停用" : profile.apiKeyConfigured ? "已配置" : "无 Key"}</span><button className="icon-button" title="编辑 Profile" aria-label="编辑 Profile" onClick={() => { setProfileError(""); setProfileDraft({ id: profile.id, name: profile.name, baseUrl: profile.baseUrl, model: profile.model, apiKey: "", enabled: profile.enabled, priority: profile.priority, timeoutMs: profile.timeoutMs, failureAction: profile.failureAction ?? "inherit" }); }}><Edit3 size={14} /></button>{profile.id !== "default" && <button className="icon-button danger-button" title="删除 Profile" aria-label="删除 Profile" onClick={async () => {
            if (!window.confirm(`确定删除 Profile“${profile.name}”吗？`)) return;
            try { await api(`/api/v1/ai-profiles/${profile.id}`, { method: "DELETE" }); await refreshProfiles(); }
            catch (failure) { setError(failure instanceof Error ? failure.message : "Profile 删除失败"); }
          }}><Trash2 size={14} /></button>}</div>) : <div className="empty-state">暂无可用 Profile</div>}</div>
          <p className="panel-meta">Key 仅在服务端加密保存；站点可在编辑器中选择 Profile。</p>
        </Panel>
        <Panel title="审核与等候室">
          <label className="field-label">审核模式<select value={draft.auditMode} onChange={(event) => updateDraft({ auditMode: event.target.value as Settings["auditMode"] })}><option value="sync">同步审核</option><option value="async">异步审核</option></select></label>
          <div className="form-grid compact-grid"><label className="field-label">异步基础封禁（秒）<input type="number" value={draft.asyncBanBaseSeconds} onChange={(event) => updateDraft({ asyncBanBaseSeconds: Number(event.target.value) })} /></label><label className="field-label">递增（秒）<input type="number" value={draft.asyncBanIncrementSeconds} onChange={(event) => updateDraft({ asyncBanIncrementSeconds: Number(event.target.value) })} /></label><label className="field-label">最大封禁（秒）<input type="number" value={draft.asyncBanMaxSeconds} onChange={(event) => updateDraft({ asyncBanMaxSeconds: Number(event.target.value) })} /></label></div>
          <label className="check-label"><input type="checkbox" checked={draft.waitRoomDefaults.enabled} onChange={(event) => updateDraft({ waitRoomDefaults: { ...draft.waitRoomDefaults, enabled: event.target.checked } })} />启用默认等候室</label>
          <div className="form-grid compact-grid"><label className="field-label">活动请求上限<input type="number" value={draft.waitRoomDefaults.maxActive} onChange={(event) => updateDraft({ waitRoomDefaults: { ...draft.waitRoomDefaults, maxActive: Number(event.target.value) } })} /></label><label className="field-label">队列上限<input type="number" value={draft.waitRoomDefaults.maxQueue} onChange={(event) => updateDraft({ waitRoomDefaults: { ...draft.waitRoomDefaults, maxQueue: Number(event.target.value) } })} /></label><label className="field-label">等待超时（秒）<input type="number" value={draft.waitRoomDefaults.timeoutSeconds} onChange={(event) => updateDraft({ waitRoomDefaults: { ...draft.waitRoomDefaults, timeoutSeconds: Number(event.target.value) } })} /></label></div>
        </Panel>
      </div>
      <div className="two-column settings-layout">
        <Panel title="IP 白名单与恶意库">
          <label className="field-label">白名单 CIDR（一行一个）<textarea rows={4} value={draft.whitelistCidrs.join("\n")} onChange={(event) => updateDraft({ whitelistCidrs: event.target.value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean) })} /></label>
          <label className="field-label">恶意 IP/CIDR（一行一个）<textarea rows={4} value={draft.maliciousIpCidrs.join("\n")} onChange={(event) => updateDraft({ maliciousIpCidrs: event.target.value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean) })} /></label>
          <IpFeedFields preview={async (content, format) => (await api<{ data: string[] }>("/api/v1/ip-feed-previews", { method: "POST", body: JSON.stringify({ content, format }) })).data} onApply={(target, values) => updateDraft({ [target]: [...new Set([...draft[target], ...values])] })} />
        </Panel>
        <Panel title="人机验证">
          <label className="check-label"><input type="checkbox" checked={draft.captcha.enabled} onChange={(event) => updateDraft({ captcha: { ...draft.captcha, enabled: event.target.checked } })} />启用人机验证</label>
          <label className="field-label">供应商<select value={draft.captcha.provider} onChange={(event) => updateDraft({ captcha: { ...draft.captcha, provider: event.target.value as Settings["captcha"]["provider"] } })}><option value="local">本地 PoW 挑战</option><option value="turnstile">Turnstile</option><option value="hcaptcha">hCaptcha</option><option value="recaptcha">reCAPTCHA</option></select></label>
          <label className="field-label">触发条件<select value={draft.captcha.trigger ?? "always"} onChange={(event) => updateDraft({ captcha: { ...draft.captcha, trigger: event.target.value as "always" | "cc" } })}><option value="always">所有访客</option><option value="cc">达到 CC 限制时</option></select></label>
          {draft.captcha.provider !== "local" && <>
            <label className="field-label">Site Key<input value={draft.captcha.siteKey} onChange={(event) => updateDraft({ captcha: { ...draft.captcha, siteKey: event.target.value } })} /></label>
            <label className="field-label">Secret Key<input type="password" autoComplete="new-password" disabled={clearCaptchaSecret} value={captchaSecret} placeholder={draft.captcha.secretConfigured ? "已配置，留空保持原值" : "未配置"} onChange={(event) => setCaptchaSecret(event.target.value)} /></label>
            <label className="check-label"><input type="checkbox" checked={clearCaptchaSecret} onChange={(event) => setClearCaptchaSecret(event.target.checked)} />保存时移除 Secret</label>
            <label className="field-label">验证超时（毫秒）<input type="number" min={100} max={30000} value={draft.captcha.timeoutMs ?? 5000} onChange={(event) => updateDraft({ captcha: { ...draft.captcha, timeoutMs: Number(event.target.value) } })} /></label>
            <label className="field-label">供应商不可用时<select value={draft.captcha.failureAction ?? "block"} onChange={(event) => updateDraft({ captcha: { ...draft.captcha, failureAction: event.target.value as "allow" | "block" } })}><option value="block">拒绝验证</option><option value="allow">允许继续</option></select></label>
          </>}
        </Panel>
      </div>
      <Panel title="GeoIP 数据库"><GeoIpFields /></Panel>
      {profileDraft && <div className="modal-backdrop site-editor-backdrop" role="presentation">
        <section ref={profileDialogRef} className="site-editor" role="dialog" aria-modal="true" aria-label="编辑 API Profile">
          <div className="drawer-head"><div><p className="eyebrow">API Profile</p><h2>{profileDraft.id ? "编辑 Profile" : "新增 Profile"}</h2></div><button className="icon-button" onClick={() => { setProfileDraft(null); setProfileError(""); }} aria-label="关闭" title="关闭"><X size={16} /></button></div>
          <div className="site-editor-body">
            <label className="field-label">名称<input value={profileDraft.name} onChange={(event) => setProfileDraft({ ...profileDraft, name: event.target.value })} /></label>
            <label className="field-label">Base URL<input value={profileDraft.baseUrl} onChange={(event) => setProfileDraft({ ...profileDraft, baseUrl: event.target.value })} /></label>
            <label className="field-label">模型<input value={profileDraft.model} onChange={(event) => setProfileDraft({ ...profileDraft, model: event.target.value })} /></label>
            <label className="field-label">API Key<input type="password" disabled={profileDraft.clearKey} value={profileDraft.apiKey} onChange={(event) => setProfileDraft({ ...profileDraft, apiKey: event.target.value })} placeholder="留空表示保持原值" autoComplete="new-password" /></label>
            {profileDraft.id && <label className="check-label"><input type="checkbox" checked={profileDraft.clearKey ?? false} onChange={(event) => setProfileDraft({ ...profileDraft, clearKey: event.target.checked })} />保存时移除 Key</label>}
            <div className="form-grid compact-grid"><label className="field-label">优先级<input type="number" min={0} max={100000} value={profileDraft.priority} onChange={(event) => setProfileDraft({ ...profileDraft, priority: Number(event.target.value) })} /></label><label className="field-label">超时（毫秒）<input type="number" min={100} max={60000} value={profileDraft.timeoutMs} onChange={(event) => setProfileDraft({ ...profileDraft, timeoutMs: Number(event.target.value) })} /></label></div>
            <label className="field-label">审核失败时<select value={profileDraft.failureAction ?? "inherit"} onChange={(event) => setProfileDraft({ ...profileDraft, failureAction: event.target.value as "inherit" | "allow" | "block" })}><option value="inherit">继承站点策略</option><option value="allow">放行并记录</option><option value="block">阻断</option></select></label>
            <label className="check-label"><input type="checkbox" checked={profileDraft.enabled} onChange={(event) => setProfileDraft({ ...profileDraft, enabled: event.target.checked })} />启用 Profile</label>
          </div>
          {profileError && <div className="form-error" role="alert"><AlertTriangle size={15} />{profileError}</div>}
          <div className="site-editor-actions"><button className="secondary-button" onClick={() => { setProfileDraft(null); setProfileError(""); }}>取消</button><button className="primary-button" onClick={() => void saveProfile()}><Save size={15} />保存 Profile</button></div>
        </section>
      </div>}
    </section>
  );
}

function modeLabel(mode: Mode): string {
  return mode === "ai" ? "AI 判断" : mode === "hybrid" ? "混合模式" : "传统规则";
}

function thresholdLabel(settings: Settings): string {
  return settings.strength === "custom" ? `${Math.round(settings.customThreshold * 100)}%` : `${thresholds[settings.strength]}%`;
}

function ErrorNotice({ message, onRetry }: { message: string; onRetry: () => void }) {
  return <div className="error-notice"><AlertTriangle size={15} /><span>{message}</span><button className="text-button" onClick={onRetry}>重试</button></div>;
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

function EventList({ events }: { events: EventRecord[] }) {
  if (!events.length) return <div className="empty-state"><Activity size={22} /><span>还没有请求事件</span></div>;
  return <div className="event-list">{events.map((event) => <div className="event-row" key={event.id}><span className={`event-status ${event.action}`} /><div className="event-copy"><strong>{event.path}</strong><span>{event.method} · {event.reason} · {event.country ?? "未知地区"}</span></div><span className="event-score">{scoreLabel(event.score)}</span><span className="event-time">{formatTime(event.createdAt)}</span></div>)}</div>;
}

function EventTable({ events, onSelect }: { events: EventRecord[]; onSelect: (event: EventRecord) => void }) {
  if (!events.length) return <div className="empty-state"><Activity size={22} /><span>没有符合筛选条件的事件</span></div>;
  return <div className="table-wrap"><table><thead><tr><th>动作</th><th>请求</th><th>来源</th><th>模式</th><th>Jev 分数</th><th>规则命中</th><th>时间</th></tr></thead><tbody>{events.map((event) => <tr key={event.id} onClick={() => onSelect(event)}><td><span className={`status-badge ${event.action === "allow" ? "green" : event.action === "block" ? "red" : "amber"}`}>{event.action === "allow" ? "放行" : event.action === "block" ? "拦截" : "错误"}</span></td><td><strong>{event.method} {event.path}</strong><small>{event.requestId.slice(0, 12)}</small></td><td><strong>{event.ip ?? "unknown"}</strong><small>{event.country ?? "未知地区"}{event.region ? ` · ${event.region}` : ""}</small></td><td>{event.mode === "hybrid" ? "混合" : event.mode === "ai" ? "AI" : "规则"}</td><td>{scoreLabel(event.score)}{event.threshold !== undefined && <small> / {scoreLabel(event.threshold)}</small>}</td><td>{event.matchedRules.length ? event.matchedRules.map((rule) => rule.ruleId).join(", ") : "—"}</td><td>{formatTime(event.createdAt)}</td></tr>)}</tbody></table></div>;
}

function EventDetails({ event, onClose }: { event: EventRecord; onClose: () => void }) {
  const [seed, setSeed] = useState<ExceptionSeed | undefined>();
  const [dirty, setDirty] = useState(false);
  const close = () => { if (!dirty || window.confirm("例外有未保存修改，确定关闭吗？")) onClose(); };
  const [rules, setRules] = useState<Rule[]>([]);
  useEffect(() => { void api<{ data: Rule[] }>("/api/v1/rules").then((result) => setRules(result.data)).catch(() => {}); }, []);
  return <div className="modal-backdrop" role="presentation" onClick={close}><aside className="event-drawer" role="dialog" aria-label="事件详情" onClick={(eventClick) => eventClick.stopPropagation()}>
    <div className="drawer-head"><div><p className="eyebrow">事件详情</p><h2>{event.method} {event.path}</h2></div><button className="icon-button" title="关闭详情" onClick={close}><X size={16} /></button></div>
    <div className="detail-grid"><span>动作</span><strong>{event.action === "block" ? "已拦截" : event.action === "allow" ? "已放行" : "错误"}</strong><span>Request ID</span><code>{event.requestId}</code><span>来源</span><strong>{event.ip ?? "未知 IP"}</strong><span>地区</span><strong>{[event.country, event.region, event.city].filter(Boolean).join(" · ") || "未知地区"}</strong><span>ASN</span><strong>{event.asn ? `AS${event.asn}` : "未知"}</strong><span>Jev</span><strong>{scoreLabel(event.score)}{event.threshold !== undefined ? ` / ${scoreLabel(event.threshold)}` : ""}</strong><span>状态码</span><strong>{event.statusCode ?? "—"}</strong><span>原因</span><strong>{event.reason}</strong></div>
    <div className="detail-grid"><span>站点 / 入口</span><strong>{event.siteId ?? "unknown"}{event.listenPort ? ` · :${event.listenPort}` : ""}</strong><span>策略版本</span><strong>{event.policyRevision ?? "未知"}</strong><span>检测模块</span><strong>{event.module ?? "未知"}</strong><span>本地检查</span><strong>{event.localInspectionComplete ? "完整" : "未完整执行"}</strong><span>AI 检查</span><strong>{event.aiInspectionComplete === undefined ? "未调用" : event.aiInspectionComplete ? "完整" : `不完整 · ${event.aiOmittedReason ?? "未知"}`}</strong><span>观察命中</span><strong>{event.wouldBlock ? "是" : "否"}</strong><span>应用例外</span><strong>{event.exceptionIds?.join(", ") || "无"}</strong></div>
    <div className="detail-section"><h3>命中规则</h3>{event.matchedRules.length ? event.matchedRules.map((rule) => <div className="detail-rule" key={rule.ruleId}><strong>{rule.ruleId}</strong><span>{rule.name} · {rule.category}</span></div>) : <span className="panel-meta">没有规则命中</span>}</div>
    <div className="detail-section"><h3>AI 状态</h3><pre>{event.ai ? JSON.stringify(event.ai, null, 2) : "没有 AI 决策"}</pre></div>
    <div className="detail-section"><h3>字段证据</h3>{event.matchedRules.map((rule) => <div className="detail-rule" key={rule.ruleId}><strong>{rule.ruleId} · {rule.target}:{rule.field || "未知字段"}</strong><span>{rule.snippet ?? "[OMITTED]"}</span>{event.siteId && event.siteId !== "unknown" && rule.field && ["body", "query", "header", "cookie"].includes(rule.target ?? "") && <button className="secondary-button" onClick={() => setSeed({ method: event.method, path: event.path.split("?", 1)[0]!, ruleId: rule.ruleId, field: rule.field!, target: rule.target! })}><Plus size={15} />创建精确例外</button>}</div>)}</div>
    {seed && event.siteId && <ScopedRules api={api} siteId={event.siteId} kind="exceptions" rules={rules} seed={seed} onDirtyChange={setDirty} />}
  </aside></div>;
}

function LoadingRows({ count }: { count: number }) {
  return <div className="loading-rows">{Array.from({ length: count }, (_, index) => <div className="skeleton-row" key={index}><span /><span /><span /></div>)}</div>;
}

function StatusLine({ icon: Icon, label, value, state }: { icon: typeof Server; label: string; value: string; state: "good" | "warn" }) {
  return <div className="status-line"><Icon size={16} /><span>{label}</span><strong>{value}</strong><span className={`status-dot ${state === "warn" ? "amber" : ""}`} /></div>;
}

export default App;
