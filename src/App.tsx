import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import {
  Activity, ArrowDownToLine, ArrowUpRight, BadgeCheck, Binary, BookOpen,
  Check, ChevronRight, CircleAlert, Copy, Database, Download, FileImage,
  FileKey2, Fingerprint, Globe2, Hash, History, Layers3, Link2, LoaderCircle,
  LockKeyhole, Menu, Network, Radar, Search, Shield, ShieldCheck, Sparkles,
  TerminalSquare, Trash2, Upload, X,
} from 'lucide-react';
import {
  checkEmailSyntax, cleanDomain, detectInputKind, formatDate, getDomainDns, getIpInfo,
  getRdapDomain, inspectUrl, isIPv4, isIPv6, isValidDomain, queryDns, saveTextFile,
  summarizeRdap,
} from './lib/osint';
import type { DnsResult } from './lib/osint';

 type ToolId = 'overview' | 'domain' | 'ip' | 'censys' | 'url' | 'email' | 'metadata' | 'hash' | 'workspace';
 type WorkspaceEntry = {
  id: string;
  title: string;
  type: string;
  subject: string;
  createdAt: string;
  data: unknown;
 };
 type OutputState = { title: string; subject: string; data: unknown; note?: string };
type CensysLookupType = 'host' | 'webproperty' | 'certificate';

const STORAGE_KEY = 'bocil-osint-workspace-v1';

const toolDetails: Record<ToolId, { title: string; eyebrow: string; description: string }> = {
  overview: { title: 'Intelligence overview', eyebrow: 'COMMAND CENTER', description: 'Satu workspace ringan untuk membaca sinyal dari sumber publik dan memeriksa artefak secara lokal.' },
  domain: { title: 'Domain recon', eyebrow: 'PUBLIC DNS + RDAP', description: 'Periksa record DNS publik dan metadata registrasi domain yang tersedia melalui RDAP.' },
  ip: { title: 'IP intelligence', eyebrow: 'NETWORK CONTEXT', description: 'Lihat konteks alamat IP publik, ASN, organisasi jaringan, dan geolokasi perkiraan.' },
  censys: { title: 'Censys host intelligence', eyebrow: 'CENSYS PLATFORM API', description: 'Ambil rekaman host publik Censys untuk alamat IP publik dan tinjau layanan yang pernah diamati.' },
  url: { title: 'URL inspector', eyebrow: 'LOCAL ANALYSIS', description: 'Periksa struktur tautan dan indikator risiko dasar tanpa membuka tautan target.' },
  email: { title: 'Email domain check', eyebrow: 'SYNTAX + MX RECORDS', description: 'Validasi sintaks dasar alamat email dan periksa apakah domain menerbitkan record MX.' },
  metadata: { title: 'Metadata inspector', eyebrow: 'BROWSER-ONLY FILE ANALYSIS', description: 'Baca metadata foto/berkas yang didukung langsung di browser tanpa mengunggah berkas.' },
  hash: { title: 'File hash lab', eyebrow: 'WEB CRYPTO API', description: 'Hitung checksum SHA-256 dari berkas di perangkatmu. Berkas tidak dikirim ke server.' },
  workspace: { title: 'Investigation workspace', eyebrow: 'LOCAL STORAGE', description: 'Simpan hasil pilihan di browser ini dan ekspor salinan laporan kapan saja.' },
};

const navGroups = [
  { label: 'WORKSPACE', items: [{ id: 'overview' as const, label: 'Overview', icon: Layers3 }, { id: 'workspace' as const, label: 'Saved findings', icon: Database }] },
  { label: 'RECON TOOLS', items: [{ id: 'domain' as const, label: 'Domain recon', icon: Globe2 }, { id: 'ip' as const, label: 'IP intelligence', icon: Network }, { id: 'censys' as const, label: 'Censys Asset Intel', icon: Radar }, { id: 'url' as const, label: 'URL inspector', icon: Link2 }, { id: 'email' as const, label: 'Email domain', icon: Fingerprint }] },
  { label: 'LOCAL ANALYSIS', items: [{ id: 'metadata' as const, label: 'Metadata inspector', icon: FileImage }, { id: 'hash' as const, label: 'File hash lab', icon: Hash }] },
];

function App() {
  const [activeTool, setActiveTool] = useState<ToolId>('overview');
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [entries, setEntries] = useState<WorkspaceEntry[]>([]);
  const [output, setOutput] = useState<OutputState | null>(null);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState('');
  const [quickQuery, setQuickQuery] = useState('');
  const current = toolDetails[activeTool];

  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) setEntries(JSON.parse(raw) as WorkspaceEntry[]);
    } catch {
      setEntries([]);
    }
  }, []);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(''), 2800);
    return () => window.clearTimeout(timer);
  }, [toast]);

  function updateEntries(next: WorkspaceEntry[]) {
    setEntries(next);
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(next)); } catch { setToast('Penyimpanan browser penuh. Ekspor temuan dan hapus beberapa item.'); }
  }

  function setFinding(title: string, subject: string, data: unknown, note?: string) {
    setOutput({ title, subject, data, note });
  }

  function saveCurrent() {
    if (!output) return;
    const entry: WorkspaceEntry = {
      id: crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      title: output.title,
      type: activeTool,
      subject: output.subject,
      createdAt: new Date().toISOString(),
      data: output.data,
    };
    updateEntries([entry, ...entries].slice(0, 80));
    setToast('Temuan disimpan di browser ini.');
  }

  async function runQuick(event: FormEvent) {
    event.preventDefault();
    const input = quickQuery.trim();
    if (!input) { setToast('Masukkan domain, alamat IP, atau URL.'); return; }
    const kind = detectInputKind(input);
    if (kind === 'unknown') { setToast('Format belum dikenali. Coba example.com, IP publik, atau URL.'); return; }
    setLoading(true);
    try {
      if (kind === 'url') {
        const result = inspectUrl(input);
        setActiveTool('url');
        setFinding('URL inspection', result.hostname, result, 'Analisis dilakukan lokal di browser; URL target tidak dibuka.');
      } else if (kind === 'ip') {
        if (isIPv6(input) && !isIPv4(input)) throw new Error('Layanan IP ringkas saat ini hanya menerima IPv4. Pemeriksaan IPv6 belum diaktifkan di starter ini.');
        const data = await getIpInfo(input);
        setActiveTool('ip');
        setFinding('IP intelligence', input, data, 'Geolokasi bersifat perkiraan dan dapat menunjuk ke ISP, bukan alamat seseorang.');
      } else {
        const domain = cleanDomain(input);
        const [dns, rdap] = await Promise.all([getDomainDns(domain), getRdapDomain(domain).catch((error: unknown) => ({ rdapError: error instanceof Error ? error.message : 'Data RDAP tidak tersedia.' }))]);
        setActiveTool('domain');
        setFinding('Domain reconnaissance', domain, { domain, dns, rdap: 'rdapError' in rdap ? rdap : summarizeRdap(rdap) }, 'Data berasal dari DNS-over-HTTPS publik dan layanan RDAP; hasil dapat berbeda antarpenyedia.');
      }
    } catch (error) {
      setToast(error instanceof Error ? error.message : 'Pemeriksaan gagal. Coba lagi.');
    } finally {
      setLoading(false);
    }
  }

  function goTo(id: ToolId) {
    setActiveTool(id);
    setMobileNavOpen(false);
    setOutput(null);
  }

  function deleteEntry(id: string) { updateEntries(entries.filter((entry) => entry.id !== id)); setToast('Temuan dihapus.'); }
  function exportEntries() { saveTextFile('bocil-osint-findings.json', JSON.stringify({ exportedAt: new Date().toISOString(), application: 'BOCIL OSINT', entries }, null, 2), 'application/json;charset=utf-8'); }
  function exportCurrent() { if (output) saveTextFile(`bocil-osint-${slugify(output.subject)}.json`, JSON.stringify(output, null, 2), 'application/json;charset=utf-8'); }

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNavOpen ? 'sidebar-open' : ''}`}>
        <div className="brand-block">
          <div className="brand-mark"><Radar size={23} strokeWidth={1.8} /></div>
          <div className="brand-copy"><span>BOCIL<span className="brand-accent">.</span></span><small>OSINT CONSOLE</small></div>
          <button className="icon-btn mobile-close" aria-label="Tutup menu" onClick={() => setMobileNavOpen(false)}><X size={18} /></button>
        </div>
        <div className="workspace-pill"><span className="pulse-dot" /> PUBLIC INTELLIGENCE <span className="pill-version">V1.1</span></div>
        <nav className="main-nav" aria-label="Navigasi utama">
          {navGroups.map((group) => <div className="nav-group" key={group.label}>
            <div className="nav-group-label">{group.label}</div>
            {group.items.map(({ id, label, icon: Icon }) => <button key={id} className={`nav-item ${activeTool === id ? 'active' : ''}`} onClick={() => goTo(id)}>
              <Icon size={17} strokeWidth={1.8} /><span>{label}</span>{activeTool === id && <span className="active-marker" />}
            </button>)}
          </div>)}
        </nav>
        <div className="sidebar-bottom">
          <div className="privacy-card"><div className="privacy-icon"><LockKeyhole size={17} /></div><div><strong>Local-first by design</strong><p>Tanpa akun. Temuan tersimpan di browser perangkat ini.</p></div></div>
          <div className="sidebar-foot"><span>BUILD 1.1.0</span><span><span className="status-dot" /> OPERATIONAL</span></div>
        </div>
      </aside>
      {mobileNavOpen && <button aria-label="Tutup navigasi" className="nav-backdrop" onClick={() => setMobileNavOpen(false)} />}

      <main className="main-shell">
        <header className="topbar">
          <div className="topbar-left"><button className="icon-btn menu-trigger" aria-label="Buka menu" onClick={() => setMobileNavOpen(true)}><Menu size={20} /></button><span className="breadcrumb">BOCIL OSINT</span><ChevronRight size={14} className="breadcrumb-chevron" /><span className="breadcrumb-current">{current.title}</span></div>
          <div className="topbar-right"><span className="live-indicator"><span className="pulse-dot" /> SYSTEM READY</span><span className="topbar-divider" /><button className="topbar-help" onClick={() => setToast('Gunakan hanya data publik dan lakukan pemeriksaan pada aset yang berhak kamu audit.')}><ShieldCheck size={16} /><span>Responsible use</span></button></div>
        </header>

        <div className="content-area">
          <div className="page-heading">
            <div><div className="eyebrow"><span className="eyebrow-line" />{current.eyebrow}</div><h1>{current.title}<span className="title-period">.</span></h1><p>{current.description}</p></div>
            <div className="heading-meta"><div className="meta-icon"><Activity size={17} /></div><div><span>SESSION</span><strong>LOCAL / {entries.length.toString().padStart(2, '0')} SAVED</strong></div></div>
          </div>

          {activeTool === 'overview' && <Overview
            entries={entries} quickQuery={quickQuery} setQuickQuery={setQuickQuery} runQuick={runQuick}
            loading={loading} goTo={goTo} setFinding={setFinding} setActiveTool={setActiveTool}
          />}
          {activeTool === 'domain' && <DomainTool setFinding={setFinding} output={output} loading={loading} setLoading={setLoading} />}
          {activeTool === 'ip' && <IpTool setFinding={setFinding} loading={loading} setLoading={setLoading} />}
          {activeTool === 'censys' && <CensysTool setFinding={setFinding} />}
          {activeTool === 'url' && <UrlTool setFinding={setFinding} />}
          {activeTool === 'email' && <EmailTool setFinding={setFinding} loading={loading} setLoading={setLoading} />}
          {activeTool === 'metadata' && <MetadataTool setFinding={setFinding} />}
          {activeTool === 'hash' && <HashTool setFinding={setFinding} />}
          {activeTool === 'workspace' && <Workspace entries={entries} deleteEntry={deleteEntry} exportEntries={exportEntries} setFinding={setFinding} setActiveTool={setActiveTool} />}

          {output && activeTool !== 'overview' && activeTool !== 'workspace' && <ResultPanel output={output} onSave={saveCurrent} onExport={exportCurrent} />}
          <footer className="page-footer"><div><span className="footer-emblem"><Shield size={13} /></span> BOCIL OSINT <span className="footer-muted">/ INFORMATION IS NOT ATTRIBUTION</span></div><div>BUILT FOR PUBLIC DATA RESEARCH <span className="footer-dot">•</span> V1.1.0</div></footer>
        </div>
      </main>
      {toast && <div className="toast" role="status"><CircleAlert size={17} /><span>{toast}</span><button aria-label="Tutup notifikasi" onClick={() => setToast('')}><X size={15} /></button></div>}
    </div>
  );
}

function Overview({ entries, quickQuery, setQuickQuery, runQuick, loading, goTo }: {
  entries: WorkspaceEntry[]; quickQuery: string; setQuickQuery: (value: string) => void;
  runQuick: (event: FormEvent) => void; loading: boolean; goTo: (id: ToolId) => void;
  setFinding: (title: string, subject: string, data: unknown, note?: string) => void;
  setActiveTool: (id: ToolId) => void;
}) {
  const toolCards: { id: ToolId; icon: typeof Globe2; number: string; title: string; desc: string; tag: string }[] = [
    { id: 'domain', icon: Globe2, number: '01', title: 'Domain recon', desc: 'DNS records, NS, MX, TXT, CAA and RDAP domain events.', tag: 'DNS / RDAP' },
    { id: 'ip', icon: Network, number: '02', title: 'IP intelligence', desc: 'Public IP context, ASN, provider and approximate network location.', tag: 'IP / ASN' },
    { id: 'censys', icon: Radar, number: '03', title: 'Censys Asset Intel', desc: 'Host records and observed services from the Censys Platform dataset.', tag: 'CENSYS API' },
    { id: 'url', icon: Link2, number: '04', title: 'URL inspector', desc: 'Local structure checks and suspicious URL indicators.', tag: 'LOCAL CHECK' },
    { id: 'email', icon: Fingerprint, number: '05', title: 'Email domain', desc: 'Basic format validation and public MX record lookup.', tag: 'EMAIL / MX' },
    { id: 'metadata', icon: FileImage, number: '06', title: 'Metadata inspector', desc: 'Read available image metadata on this device only.', tag: 'EXIF / LOCAL' },
    { id: 'hash', icon: Hash, number: '07', title: 'File hash lab', desc: 'Calculate SHA-256 checksums without uploading files.', tag: 'SHA-256' },
  ];
  return <>
    <section className="hero-panel">
      <div className="hero-grid" />
      <div className="hero-copy"><div className="hero-kicker"><span className="hero-kicker-mark"><Sparkles size={13} /></span> OPEN-SOURCE INTELLIGENCE WORKSPACE</div><h2>Investigate the<br /><em>visible web.</em></h2><p>Mulai dari satu indikator. Kumpulkan konteks dari sumber terbuka, periksa sinyalnya, lalu simpan hasil yang relevan untuk ditinjau kembali.</p>
        <form className="quick-search" onSubmit={runQuick}><Search size={18} /><input value={quickQuery} onChange={(e) => setQuickQuery(e.target.value)} placeholder="Masukkan domain, IP publik, atau URL..." aria-label="Domain, alamat IP, atau URL" /><button type="submit" disabled={loading}>{loading ? <LoaderCircle size={17} className="spin" /> : <>ANALYZE <ArrowUpRight size={15} /></>}</button></form>
        <div className="search-hint"><span><kbd>ENTER</kbd> untuk mulai</span><span><LockKeyhole size={13} /> Jangan masukkan kata sandi atau token rahasia.</span></div>
      </div>
      <div className="hero-art" aria-hidden="true"><div className="radar-orbit orbit-one" /><div className="radar-orbit orbit-two" /><div className="radar-orbit orbit-three" /><div className="radar-center"><Radar size={52} strokeWidth={1.1} /></div><div className="radar-sweep" /><div className="radar-cross cross-a" /><div className="radar-cross cross-b" /><div className="radar-label radar-label-top">PUBLIC SIGNAL <span>01</span></div><div className="radar-label radar-label-bottom">NO ACTIVE SCANNING</div><div className="radar-coordinate">0.000 / WEB</div></div>
      <div className="hero-bottomline"><span><span className="status-dot" /> SOURCES: PUBLIC / OPEN</span><span>NO CREDENTIALS REQUIRED <span className="footer-dot">•</span> SESSION-LOCAL STORAGE</span></div>
    </section>

    <div className="section-heading"><div><div className="eyebrow">TOOLKIT / 07 MODULES</div><h2>Investigation tools</h2></div><span className="section-side-note">SELECT A MODULE <ArrowDownToLine size={13} /></span></div>
    <section className="tool-grid">
      {toolCards.map(({ id, icon: Icon, number, title, desc, tag }) => <button className="tool-card" key={id} onClick={() => goTo(id)}><div className="tool-card-top"><span className="tool-card-number">{number} / 07</span><span className="tool-card-icon"><Icon size={19} /></span></div><h3>{title}<ChevronRight size={16} /></h3><p>{desc}</p><div className="tool-card-bottom"><span>{tag}</span><span className="card-open"><ArrowUpRight size={15} /></span></div></button>)}
    </section>

    <section className="overview-lower">
      <div className="panel-card activity-card"><div className="card-heading"><div><span className="mini-label">WORKSPACE / HISTORY</span><h3>Recent findings</h3></div><button className="text-action" onClick={() => goTo('workspace')}>VIEW ALL <ArrowUpRight size={14} /></button></div>
        {entries.length ? <div className="recent-list">{entries.slice(0, 4).map((entry) => <div className="recent-row" key={entry.id}><div className="recent-type-icon"><FileKey2 size={16} /></div><div className="recent-main"><strong>{entry.title}</strong><span>{entry.subject}</span></div><div className="recent-time">{formatDate(entry.createdAt)}</div></div>)}</div> : <div className="empty-state"><div className="empty-glyph"><Database size={21} /></div><strong>No findings saved yet</strong><span>Hasil pemeriksaan yang kamu simpan akan muncul di sini.</span></div>}
      </div>
      <div className="panel-card methodology-card"><div className="method-icon"><ShieldCheck size={18} /></div><div className="mini-label">RESEARCH PRINCIPLES</div><h3>Evidence over assumptions.</h3><p>Tool ini membantu mengumpulkan sinyal publik. Hasil teknis bukan bukti identitas seseorang, dan lokasi IP bukan alamat personal yang presisi.</p><div className="method-line"><span /><span /><span /></div><div className="method-bottom"><span><BadgeCheck size={14} /> Responsible use</span><span>01 — 03</span></div></div>
    </section>
  </>;
}

function ToolHeader({ icon, title, sub, extra }: { icon: ReactNode; title: string; sub: string; extra?: ReactNode }) {
  return <div className="tool-workspace-header"><div className="tool-workspace-icon">{icon}</div><div><h2>{title}</h2><p>{sub}</p></div>{extra && <div className="tool-header-extra">{extra}</div>}</div>;
}

function ToolLayout({ children, aside }: { children: ReactNode; aside?: ReactNode }) {
  return <section className="tool-layout"><div className="tool-main-column">{children}</div>{aside && <aside className="tool-aside">{aside}</aside>}</section>;
}

function DomainTool({ setFinding, output, loading, setLoading }: { setFinding: (title: string, subject: string, data: unknown, note?: string) => void; output: OutputState | null; loading: boolean; setLoading: (v: boolean) => void }) {
  const [domainInput, setDomainInput] = useState('');
  const [dns, setDns] = useState<DnsResult[] | null>(null);
  const [rdapSummary, setRdapSummary] = useState<unknown>(null);
  const [error, setError] = useState('');
  async function submit(event: FormEvent) {
    event.preventDefault();
    const domain = cleanDomain(domainInput);
    if (!isValidDomain(domain)) { setError('Masukkan nama domain yang valid, misalnya example.com.'); return; }
    setError(''); setLoading(true); setDns(null); setRdapSummary(null);
    try {
      const [dnsData, rdapData] = await Promise.all([
        getDomainDns(domain),
        getRdapDomain(domain).then((data) => summarizeRdap(data)).catch((e: unknown) => ({ unavailable: e instanceof Error ? e.message : 'RDAP tidak tersedia.' })),
      ]);
      setDns(dnsData); setRdapSummary(rdapData);
      setFinding('Domain reconnaissance', domain, { domain, dns: dnsData, rdap: rdapData }, 'DNS data via Google Public DNS-over-HTTPS; registrasi via RDAP. Kegagalan salah satu sumber tidak berarti domain aman atau tidak terdaftar.');
    } catch (e) { setError(e instanceof Error ? e.message : 'Pemeriksaan gagal.'); }
    finally { setLoading(false); }
  }
  return <>
    <ToolLayout aside={<><SourceCard title="Data sources" items={['Google Public DNS-over-HTTPS', 'RDAP bootstrap / registrar service']} /><NoticeCard title="Passive lookup" text="Pemeriksaan ini meminta data DNS publik dan RDAP. Tool tidak melakukan port scan, eksploitasi, atau perubahan pada domain target." /></>}>
      <div className="panel-card tool-form-card"><ToolHeader icon={<Globe2 size={20} />} title="Domain reconnaissance" sub="Resolve common DNS records and request public registration data." /><form className="tool-form" onSubmit={submit}><label htmlFor="domain-input">DOMAIN NAME</label><div className="input-row"><div className="field-with-icon"><Globe2 size={17} /><input id="domain-input" value={domainInput} onChange={(e) => setDomainInput(e.target.value)} placeholder="example.com" autoCapitalize="none" autoCorrect="off" /></div><button className="primary-btn" disabled={loading}>{loading ? <LoaderCircle className="spin" size={16} /> : <><Radar size={16} /> RUN RECON</>}</button></div>{error && <p className="error-line"><CircleAlert size={14} />{error}</p>}<div className="form-helper"><span>Records: A · AAAA · MX · NS · TXT · CAA</span><span><LockKeyhole size={13} /> Public data</span></div></form></div>
      {dns && <div className="panel-card data-card"><div className="card-heading"><div><span className="mini-label">DNS RESOLUTION</span><h3>{cleanDomain(domainInput)}</h3></div><span className="result-chip"><span className="status-dot" /> COMPLETE</span></div><div className="dns-grid">{dns.map((group) => <div className="dns-record" key={group.type}><div className="dns-record-head"><strong>{group.type}</strong><span>{group.answers.length} record{group.answers.length === 1 ? '' : 's'}</span></div>{group.answers.length ? group.answers.map((answer, index) => <div className="dns-answer" key={`${group.type}-${index}`}><span>{answer.data ?? '—'}</span><small>TTL {answer.TTL ?? '—'}</small></div>) : <div className="dns-empty">No answer / unavailable</div>}</div>)}</div><div className="rdap-subpanel"><div className="mini-label">REGISTRATION DATA / RDAP</div><pre>{JSON.stringify(rdapSummary, null, 2)}</pre></div></div>}
    </ToolLayout>
    {!dns && !output && <div className="inline-tip"><Sparkles size={16} /><span><strong>Tip:</strong> Gunakan domain tanpa path URL. Record TXT dapat berisi konfigurasi email atau verifikasi layanan, tetapi tidak mengungkap seluruh konfigurasi internal.</span></div>}
  </>;
}

function IpTool({ setFinding, loading, setLoading }: { setFinding: (title: string, subject: string, data: unknown, note?: string) => void; loading: boolean; setLoading: (v: boolean) => void }) {
  const [ip, setIp] = useState(''); const [error, setError] = useState(''); const [data, setData] = useState<Record<string, unknown> | null>(null);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!isIPv4(ip.trim())) { setError('Untuk versi awal, masukkan alamat IPv4 publik yang valid.'); return; }
    const parts = ip.trim().split('.').map(Number);
    if (parts[0] === 10 || parts[0] === 127 || parts[0] === 0 || (parts[0] === 192 && parts[1] === 168) || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 169 && parts[1] === 254)) { setError('Alamat tersebut adalah IPv4 privat/khusus dan tidak cocok untuk lookup publik.'); return; }
    setError(''); setLoading(true); setData(null);
    try { const result = await getIpInfo(ip.trim()); setData(result); setFinding('IP intelligence', ip.trim(), result, 'Konteks lokasi dari basis data IP bersifat perkiraan; bisa menunjuk ke jaringan/ISP, bukan individu.'); }
    catch (e) { setError(e instanceof Error ? e.message : 'Lookup IP gagal.'); }
    finally { setLoading(false); }
  }
  const conn = (data?.connection ?? {}) as Record<string, unknown>; const tz = (data?.timezone ?? {}) as Record<string, unknown>;
  return <ToolLayout aside={<><SourceCard title="Data sources" items={['ipwho.is public IP API', 'Network / ASN metadata provided by service']} /><NoticeCard title="Location is approximate" text="Geolokasi IP biasanya menunjukkan perkiraan lokasi ISP, gateway, atau pusat jaringan. Jangan gunakan untuk menyimpulkan alamat rumah atau identitas pemilik." /></>}>
    <div className="panel-card tool-form-card"><ToolHeader icon={<Network size={20} />} title="IP intelligence" sub="Inspect context for a public IPv4 address." /><form className="tool-form" onSubmit={submit}><label htmlFor="ip-input">PUBLIC IPV4 ADDRESS</label><div className="input-row"><div className="field-with-icon"><Network size={17} /><input id="ip-input" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="1.1.1.1" inputMode="decimal" /></div><button className="primary-btn" disabled={loading}>{loading ? <LoaderCircle className="spin" size={16} /> : <><Radar size={16} /> LOOKUP IP</>}</button></div>{error && <p className="error-line"><CircleAlert size={14} />{error}</p>}<div className="form-helper"><span>Public IPv4 only in this build</span><span><LockKeyhole size={13} /> No login</span></div></form></div>
    {data && <div className="panel-card ip-result-card"><div className="ip-hero"><div className="ip-hero-icon"><Network size={24} /></div><div><span className="mini-label">IP ADDRESS</span><h3>{String(data.ip ?? ip)}</h3><p>{String(data.type ?? 'IP')} <span>•</span> {String(data.country ?? 'Unknown')} {data.country_code ? `(${String(data.country_code)})` : ''}</p></div><span className="result-chip"><span className="status-dot" /> RESOLVED</span></div><div className="metric-grid"><Metric label="CITY / REGION" value={[data.city, data.region].filter(Boolean).join(', ') || 'Not available'} /><Metric label="ISP / ORGANIZATION" value={String(conn.isp ?? conn.org ?? 'Not available')} /><Metric label="ASN" value={conn.asn ? `AS${String(conn.asn).replace(/^AS/i, '')}` : 'Not available'} /><Metric label="TIMEZONE" value={String(tz.id ?? 'Not available')} /><Metric label="CONTINENT" value={String(data.continent ?? 'Not available')} /><Metric label="COUNTRY" value={String(data.country ?? 'Not available')} /></div><div className="rdap-subpanel"><div className="mini-label">RAW RESPONSE</div><pre>{JSON.stringify(data, null, 2)}</pre></div></div>}
  </ToolLayout>;
}

function CensysTool({ setFinding }: { setFinding: (title: string, subject: string, data: unknown, note?: string) => void }) {
  const [lookupType, setLookupType] = useState<CensysLookupType>('host');
  const [query, setQuery] = useState('');
  const [loadingCensys, setLoadingCensys] = useState(false);
  const [error, setError] = useState('');
  const [record, setRecord] = useState<Record<string, unknown> | null>(null);
  const [queriedLabel, setQueriedLabel] = useState('');
  const [resultType, setResultType] = useState<CensysLookupType>('host');

  const prompts: Record<CensysLookupType, { label: string; placeholder: string; hint: string }> = {
    host: { label: 'PUBLIC IP ADDRESS / IPV4 OR IPV6', placeholder: '8.8.8.8', hint: 'Host record · observed services · ASN context when available' },
    webproperty: { label: 'WEB PROPERTY / HOSTNAME:PORT', placeholder: 'example.com:443', hint: 'Lookup one host/domain web property with a port, e.g. example.com:443' },
    certificate: { label: 'CERTIFICATE SHA-256 FINGERPRINT', placeholder: 'Paste a 64-character SHA-256 fingerprint', hint: 'Paste the certificate fingerprint as 64 hex characters; colons are optional' },
  };

  async function submit(event: FormEvent) {
    event.preventDefault();
    const value = query.trim();
    if (!value) { setError('Isi nilai yang ingin diperiksa terlebih dahulu.'); return; }
    let normalizedQuery = value;
    if (lookupType === 'host' && !(isIPv4(value) || isIPv6(value))) {
      setError('Masukkan satu alamat IPv4 atau IPv6 publik. Hostname/domain tidak diterima untuk lookup host.');
      return;
    }
    if (lookupType === 'webproperty') {
      const separator = value.lastIndexOf(':');
      const hostname = separator > 0 ? value.slice(0, separator).toLowerCase() : '';
      const portText = separator > 0 ? value.slice(separator + 1) : '';
      const port = Number(portText);
      const validHost = isIPv4(hostname) || (isValidDomain(hostname) && !hostname.includes('..'));
      if (!validHost || !/^\d{1,5}$/.test(portText) || !Number.isInteger(port) || port < 1 || port > 65535) {
        setError('Masukkan hostname/IP dan port yang valid, misalnya example.com:443.');
        return;
      }
      normalizedQuery = `${hostname}:${port}`;
    }
    if (lookupType === 'certificate') {
      normalizedQuery = value.replace(/:/g, '').toLowerCase();
      if (!/^[a-f0-9]{64}$/.test(normalizedQuery)) {
        setError('Fingerprint sertifikat harus berisi tepat 64 karakter heksadesimal SHA-256.');
        return;
      }
    }

    setError('');
    setLoadingCensys(true);
    setRecord(null);
    try {
      const response = await fetch(`/api/censys-lookup?type=${encodeURIComponent(lookupType)}&query=${encodeURIComponent(normalizedQuery)}`, {
        headers: { Accept: 'application/json' },
      });
      const payload = await response.json() as Record<string, unknown>;
      if (!response.ok) throw new Error(String(payload.error ?? `Censys lookup gagal (HTTP ${response.status}).`));
      const result = asRecord(payload.result);
      setRecord(result);
      setResultType(lookupType);
      setQueriedLabel(normalizedQuery);
      const title = lookupType === 'host' ? 'Censys host intelligence' : lookupType === 'webproperty' ? 'Censys web property' : 'Censys certificate';
      setFinding(title, normalizedQuery, {
        provider: payload.provider ?? 'Censys Platform API v3',
        lookupType,
        query: payload.query ?? normalizedQuery,
        retrievedAt: payload.retrievedAt ?? new Date().toISOString(),
        result,
      }, 'Data adalah rekaman publik dari dataset Censys, bukan pemindaian langsung atau bukti kepemilikan. Hasil dan field yang tersedia bergantung pada paket/akses Censys.');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Censys lookup gagal.');
    } finally {
      setLoadingCensys(false);
    }
  }

  const rootRecord = record ?? {};
  const host = asRecord(rootRecord.host && typeof rootRecord.host === 'object' ? rootRecord.host : rootRecord);
  const location = asRecord(host.location);
  const autonomousSystem = asRecord(host.autonomous_system ?? host.autonomousSystem);
  const services = Array.isArray(host.services) ? host.services.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === 'object').slice(0, 12) : [];
  const asn = autonomousSystem.asn;
  const asnValue = asn === undefined || asn === null ? 'Not available' : `AS${String(asn).replace(/^AS/i, '')}`;
  const serviceRows = services.map((service, index) => {
    const representative = asRecord(service.representative_info);
    const software = Array.isArray(service.software) ? service.software.map((item) => {
      const details = asRecord(item);
      return [details.product, details.version].filter(Boolean).join(' ');
    }).filter(Boolean).slice(0, 2).join(', ') : '';
    return {
      key: `${String(service.port ?? representative.sampled_port ?? 'port')}-${index}`,
      port: String(service.port ?? representative.sampled_port ?? '—'),
      protocol: String(service.protocol ?? service.extended_service_name ?? 'Unknown'),
      transport: String(service.transport_protocol ?? '—'),
      software: software || '—',
      observed: String(service.scan_time ?? service.last_observed_at ?? '—'),
    };
  });
  const title = resultType === 'host' ? 'Censys host record' : resultType === 'webproperty' ? 'Censys web property' : 'Censys certificate';

  return <ToolLayout aside={<><SourceCard title="Censys data source" items={['Censys Platform API v3', 'Host, web property and certificate lookups', 'Available fields depend on account tier']} /><NoticeCard title="Snapshot, not a live scan" text="Censys reports what its dataset observed. Missing ports or services do not prove a host is offline or secure. Check only public assets you own or are authorized to assess." /><NoticeCard title="API key stays server-side" text="The browser calls this site's /api/censys-lookup route. The Censys token is read only from CENSYS_API_TOKEN on the server and must never use a VITE_ prefix." /></>}>
    <div className="panel-card tool-form-card"><ToolHeader icon={<Radar size={20} />} title="Censys asset intelligence" sub="Use the Censys Platform API to retrieve a known host, web property, or certificate record." /><div className="censys-mode-toggle" role="group" aria-label="Censys lookup type">
      {([{ id: 'host', label: 'HOST IP' }, { id: 'webproperty', label: 'WEB PROPERTY' }, { id: 'certificate', label: 'CERTIFICATE' }] as { id: CensysLookupType; label: string }[]).map((mode) => <button key={mode.id} type="button" className={lookupType === mode.id ? 'primary-btn small' : 'secondary-btn small'} onClick={() => { setLookupType(mode.id); setRecord(null); setError(''); }}>{mode.label}</button>)}
    </div><form className="tool-form" onSubmit={submit}><label htmlFor="censys-query-input">{prompts[lookupType].label}</label><div className="input-row"><div className="field-with-icon"><Network size={17} /><input id="censys-query-input" value={query} onChange={(e) => setQuery(e.target.value)} placeholder={prompts[lookupType].placeholder} autoCapitalize="none" autoCorrect="off" spellCheck={false} /></div><button className="primary-btn" disabled={loadingCensys}>{loadingCensys ? <LoaderCircle className="spin" size={16} /> : <><Radar size={16} /> LOOK UP</>}</button></div>{error && <p className="error-line"><CircleAlert size={14} />{error}</p>}<div className="form-helper"><span>{prompts[lookupType].hint}</span><span><LockKeyhole size={13} /> Server-side token</span></div></form></div>
    {record && resultType === 'host' && <div className="panel-card data-card"><div className="card-heading"><div><span className="mini-label">CENSYS HOST RECORD</span><h3>{String(host.ip ?? queriedLabel)}</h3></div><span className="result-chip"><span className="status-dot" /> DATA RECEIVED</span></div><div className="metric-grid"><Metric label="IP ADDRESS" value={String(host.ip ?? queriedLabel)} /><Metric label="ASN" value={asnValue} /><Metric label="NETWORK / AS NAME" value={String(autonomousSystem.name ?? autonomousSystem.description ?? 'Not available')} /><Metric label="COUNTRY" value={String(location.country ?? location.country_code ?? 'Not available')} /><Metric label="OBSERVED SERVICES" value={String(Array.isArray(host.services) ? host.services.length : 0)} /><Metric label="LAST UPDATED" value={String(host.last_updated_at ?? host.last_updated ?? 'See raw response')} /></div><div className="rdap-subpanel"><div className="mini-label">OBSERVED SERVICES / MAX 12 SHOWN</div>{serviceRows.length ? <div className="censys-services">{serviceRows.map((service) => <div className="censys-service-row" key={service.key}><div><strong>{service.protocol}</strong><span>PORT {service.port} / {service.transport}</span></div><p>{service.software}</p><small>{service.observed === '—' ? 'Observation date not provided' : service.observed}</small></div>)}</div> : <p className="censys-no-services">No service list was included in this response. Open the structured JSON below for the available fields.</p>}</div></div>}
    {record && resultType !== 'host' && <div className="panel-card data-card"><div className="card-heading"><div><span className="mini-label">CENSYS ASSET RECORD</span><h3>{title}</h3></div><span className="result-chip"><span className="status-dot" /> DATA RECEIVED</span></div><div className="metric-grid"><Metric label="LOOKUP TYPE" value={resultType.toUpperCase()} /><Metric label="QUERY / IDENTIFIER" value={queriedLabel} /><Metric label="SOURCE" value="Censys Platform API v3" /><Metric label="DETAILS" value="See structured response below" /></div><p className="censys-no-services">Review the JSON response below for all fields returned by Censys for this asset.</p></div>}
    {!record && !error && <div className="inline-tip"><ShieldCheck size={16} /><span>Rekaman Censys bergantung pada cakupan dataset, waktu pengamatan, paket akun, dan izin API. Ketiadaan data bukan bukti bahwa aset aman atau tidak aktif.</span></div>}
  </ToolLayout>;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function UrlTool({ setFinding }: { setFinding: (title: string, subject: string, data: unknown, note?: string) => void }) {
  const [url, setUrl] = useState(''); const [error, setError] = useState(''); const [result, setResult] = useState<ReturnType<typeof inspectUrl> | null>(null);
  function submit(event: FormEvent) { event.preventDefault(); try { const analysis = inspectUrl(url); setResult(analysis); setError(''); setFinding('URL inspection', analysis.hostname, analysis, 'Analisis heuristik lokal, bukan verdict reputasi. URL target tidak di-fetch.'); } catch (e) { setError(e instanceof Error ? e.message : 'URL tidak valid.'); } }
  return <ToolLayout aside={<><SourceCard title="Local analysis" items={['URL parsing via browser API', 'No remote URL request', 'No reputation lookup']} /><NoticeCard title="Heuristics are not verdicts" text="Domain sah bisa memiliki parameter panjang atau kata seperti login. Sebaliknya, phishing tidak selalu memiliki indikator ini." /></>}>
    <div className="panel-card tool-form-card"><ToolHeader icon={<Link2 size={20} />} title="URL inspector" sub="Inspect URL structure and common risk indicators without visiting the destination." /><form className="tool-form" onSubmit={submit}><label htmlFor="url-input">URL OR DOMAIN</label><div className="input-row"><div className="field-with-icon"><Link2 size={17} /><input id="url-input" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com/path" autoCapitalize="none" autoCorrect="off" /></div><button className="primary-btn" type="submit"><Shield size={16} /> INSPECT URL</button></div>{error && <p className="error-line"><CircleAlert size={14} />{error}</p>}<div className="form-helper"><span>Runs entirely in this browser</span><span><LockKeyhole size={13} /> Target not contacted</span></div></form></div>
    {result && <div className="panel-card url-result-card"><div className="card-heading"><div><span className="mini-label">LOCAL HEURISTIC ANALYSIS</span><h3>{result.hostname}</h3></div><div className={`risk-score ${result.score >= 50 ? 'risk-high' : result.score >= 20 ? 'risk-medium' : ''}`}><span>{result.score}</span><small>INDICATOR<br />SCORE / 100</small></div></div><div className="risk-track"><span style={{ width: `${result.score}%` }} /></div><div className="risk-label-row"><strong>{result.risk}</strong><span>Not a safety guarantee</span></div><div className="url-attributes">{[['PROTOCOL', result.protocol], ['HOSTNAME', result.hostname], ['PORT', result.port], ['PATH', result.path], ['QUERY PARAMETERS', result.queryParameterCount], ['FRAGMENT', result.fragmentPresent ? 'Present' : 'None']].map(([label, value]) => <div className="url-attr" key={label}><span>{label}</span><strong>{String(value)}</strong></div>)}</div><div className="indicator-list">{result.flags.map((flag, index) => <div className="indicator-row" key={`${flag.title}-${index}`}><span className={`indicator-mark ${flag.level}`}><CircleAlert size={15} /></span><div><strong>{flag.title}</strong><p>{flag.detail}</p></div><span className={`indicator-tag ${flag.level}`}>{flag.level.toUpperCase()}</span></div>)}</div><p className="subtle-note"><LockKeyhole size={14} /> Analisis ini tidak membuka URL, tidak memeriksa konten halaman, dan tidak menjamin URL aman.</p></div>}
  </ToolLayout>;
}

function EmailTool({ setFinding, loading, setLoading }: { setFinding: (title: string, subject: string, data: unknown, note?: string) => void; loading: boolean; setLoading: (v: boolean) => void }) {
  const [email, setEmail] = useState(''); const [error, setError] = useState(''); const [result, setResult] = useState<{ syntax: ReturnType<typeof checkEmailSyntax>; mx: DnsResult } | null>(null);
  async function submit(event: FormEvent) { event.preventDefault(); const syntax = checkEmailSyntax(email); if (!syntax.valid) { setResult(null); setError(syntax.reason); return; } setError(''); setLoading(true); try { const mx = await queryDns(syntax.domain, 'MX'); const payload = { syntax, mx, interpretation: mx.answers.length ? 'Domain menerbitkan record MX publik.' : 'Tidak ada jawaban MX yang ditemukan oleh resolver. Ini tidak membuktikan kotak email ada atau tidak ada.' }; setResult({ syntax, mx }); setFinding('Email domain check', syntax.domain, payload, 'Hanya sintaks dasar dan DNS MX yang diperiksa; alamat email tidak dihubungi atau diverifikasi sebagai mailbox.'); } catch (e) { setError(e instanceof Error ? e.message : 'Pemeriksaan gagal.'); } finally { setLoading(false); } }
  return <ToolLayout aside={<><SourceCard title="Checks performed" items={['Basic email syntax', 'Public MX DNS records']} /><NoticeCard title="Privacy note" text="Masukkan hanya alamat yang boleh kamu periksa. Tool ini tidak mengirim email, tidak mencoba login, dan tidak memeriksa kebocoran data pribadi." /></>}>
    <div className="panel-card tool-form-card"><ToolHeader icon={<Fingerprint size={20} />} title="Email domain check" sub="Check email syntax and mail routing configuration for its domain." /><form className="tool-form" onSubmit={submit}><label htmlFor="email-input">EMAIL ADDRESS</label><div className="input-row"><div className="field-with-icon"><Fingerprint size={17} /><input id="email-input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="analyst@example.com" autoCapitalize="none" /></div><button className="primary-btn" disabled={loading}>{loading ? <LoaderCircle className="spin" size={16} /> : <><Search size={16} /> CHECK DOMAIN</>}</button></div>{error && <p className="error-line"><CircleAlert size={14} />{error}</p>}<div className="form-helper"><span>Only public DNS MX lookup</span><span><LockKeyhole size={13} /> No mailbox probing</span></div></form></div>
    {result && <div className="panel-card email-result-card"><div className="email-verdict"><div className="email-verdict-icon"><Check size={20} /></div><div><span className="mini-label">SYNTAX CHECK</span><h3>{result.syntax.email}</h3><p>{result.syntax.reason}</p></div></div><div className="data-section-title"><span>MAIL EXCHANGE / MX</span><span>{result.mx.answers.length} answer(s)</span></div>{result.mx.answers.length ? result.mx.answers.map((answer, index) => <div className="mx-row" key={`${answer.data}-${index}`}><span className="mx-priority">{answer.data?.split(' ')[0] ?? '—'}</span><strong>{answer.data?.split(' ').slice(1).join(' ') || answer.data}</strong><small>TTL {answer.TTL ?? '—'}</small></div>) : <div className="dns-empty large">No MX answer was returned by the resolver.</div>}<p className="subtle-note"><CircleAlert size={14} /> MX record hanya menunjukkan konfigurasi email domain; tidak membuktikan alamat email tertentu aktif.</p></div>}
  </ToolLayout>;
}

function MetadataTool({ setFinding }: { setFinding: (title: string, subject: string, data: unknown, note?: string) => void }) {
  const [file, setFile] = useState<File | null>(null); const [loading, setLoading] = useState(false); const [error, setError] = useState(''); const [metadata, setMetadata] = useState<Record<string, unknown> | null>(null);
  async function readFile() { if (!file) { setError('Pilih berkas gambar terlebih dahulu.'); return; } setLoading(true); setError(''); setMetadata(null); try { const exifr = (await import('exifr')).default; const raw = await exifr.parse(file, { tiff: true, exif: true, gps: true, iptc: true, xmp: true, icc: false, jfif: true, ihdr: true }) as Record<string, unknown> | undefined; const allowed = raw ? Object.fromEntries(Object.entries(raw).filter(([, value]) => value !== undefined && typeof value !== 'function').map(([key, value]) => [key, value instanceof Date ? value.toISOString() : ArrayBuffer.isView(value) ? Array.from(value as unknown as ArrayLike<number>) : value])) : {}; const result = { fileName: file.name, fileSizeBytes: file.size, mimeType: file.type || 'unknown', lastModified: new Date(file.lastModified).toISOString(), embeddedMetadata: allowed, metadataFound: Object.keys(allowed).length > 0 }; setMetadata(result); setFinding('Metadata inspection', file.name, result, 'Berkas diproses di browser. Metadata dapat berisi informasi sensitif seperti koordinat GPS; periksa sebelum membagikan.'); } catch (e) { setError(`Berkas tidak dapat dibaca sebagai gambar ber-metadata. ${e instanceof Error ? e.message : ''}`); } finally { setLoading(false); } }
  return <ToolLayout aside={<><SourceCard title="Privacy by design" items={['File remains on your device', 'No upload endpoint configured', 'Metadata may be incomplete']} /><NoticeCard title="Check GPS metadata" text="Foto bisa menyimpan koordinat pengambilan gambar. Hati-hati ketika mengirim file kepada orang lain atau mengunggah laporan yang berisi metadata pribadi." /></>}>
    <div className="panel-card tool-form-card"><ToolHeader icon={<FileImage size={20} />} title="Metadata inspector" sub="Inspect supported image metadata in your browser." /><div className="file-drop-zone"><input id="metadata-file" type="file" accept="image/*,.jpg,.jpeg,.tif,.tiff,.webp,.png,.heic" onChange={(e) => { setFile(e.target.files?.[0] ?? null); setMetadata(null); setError(''); }} /><label htmlFor="metadata-file" className="file-drop-label"><div className="upload-icon"><Upload size={21} /></div><strong>{file ? file.name : 'Choose an image file'}</strong><span>{file ? `${(file.size / 1024).toFixed(1)} KB · ${file.type || 'unknown type'}` : 'JPG, TIFF, PNG, WebP and formats supported by the parser'}</span><span className="file-select-btn">BROWSE FILES</span></label></div>{error && <p className="error-line"><CircleAlert size={14} />{error}</p>}<div className="tool-form-action"><span><LockKeyhole size={14} /> File is processed locally</span><button className="primary-btn" onClick={readFile} disabled={!file || loading}>{loading ? <LoaderCircle className="spin" size={16} /> : <><FileImage size={16} /> READ METADATA</>}</button></div></div>
    {metadata && <div className="panel-card data-card"><div className="card-heading"><div><span className="mini-label">FILE METADATA</span><h3>{String(metadata.fileName)}</h3></div><span className="result-chip">{metadata.metadataFound ? 'METADATA FOUND' : 'BASIC INFO ONLY'}</span></div><div className="metadata-summary">{[['FILE SIZE', `${(Number(metadata.fileSizeBytes) / 1024).toFixed(1)} KB`], ['MIME TYPE', String(metadata.mimeType)], ['LAST MODIFIED', formatDate(String(metadata.lastModified))], ['EMBEDDED TAGS', String(Object.keys((metadata.embeddedMetadata ?? {}) as object).length)]].map(([l, v]) => <Metric key={l} label={l} value={v} />)}</div><div className="rdap-subpanel"><div className="mini-label">PARSED METADATA</div><pre>{JSON.stringify(metadata.embeddedMetadata, null, 2)}</pre></div></div>}
  </ToolLayout>;
}

function HashTool({ setFinding }: { setFinding: (title: string, subject: string, data: unknown, note?: string) => void }) {
  const [file, setFile] = useState<File | null>(null); const [loading, setLoading] = useState(false); const [error, setError] = useState(''); const [digest, setDigest] = useState('');
  async function hashFile() { if (!file) { setError('Pilih berkas terlebih dahulu.'); return; } setLoading(true); setError(''); setDigest(''); try { const bytes = await file.arrayBuffer(); const hashBuffer = await crypto.subtle.digest('SHA-256', bytes); const result = Array.from(new Uint8Array(hashBuffer)).map((byte) => byte.toString(16).padStart(2, '0')).join(''); setDigest(result); setFinding('File SHA-256', file.name, { fileName: file.name, sizeBytes: file.size, mimeType: file.type || 'unknown', algorithm: 'SHA-256', digest: result, calculatedAt: new Date().toISOString() }, 'Hash dihitung di browser dengan Web Crypto API; berkas tidak diunggah.'); } catch (e) { setError(e instanceof Error ? e.message : 'Hash tidak dapat dihitung. Browser mungkin tidak menyediakan Web Crypto API.'); } finally { setLoading(false); } }
  return <ToolLayout aside={<><SourceCard title="About SHA-256" items={['One-way cryptographic digest', 'Same file content → same digest', 'Different files usually → different digest']} /><NoticeCard title="Hash is not encryption" text="Hash tidak dapat digunakan untuk mengembalikan isi file. Nama file dan timestamp tidak ikut menjadi bagian hash, hanya byte isi file." /></>}>
    <div className="panel-card tool-form-card"><ToolHeader icon={<Hash size={20} />} title="File hash lab" sub="Generate a SHA-256 digest for file integrity checks." /><div className="file-drop-zone compact"><input id="hash-file" type="file" onChange={(e) => { setFile(e.target.files?.[0] ?? null); setDigest(''); setError(''); }} /><label htmlFor="hash-file" className="file-drop-label"><div className="upload-icon"><Binary size={21} /></div><strong>{file ? file.name : 'Select any file to hash'}</strong><span>{file ? `${(file.size / 1024).toFixed(1)} KB` : 'File content stays in the browser memory for processing'}</span><span className="file-select-btn">CHOOSE FILE</span></label></div>{error && <p className="error-line"><CircleAlert size={14} />{error}</p>}<div className="tool-form-action"><span><LockKeyhole size={14} /> Client-side processing</span><button className="primary-btn" onClick={hashFile} disabled={!file || loading}>{loading ? <LoaderCircle className="spin" size={16} /> : <><Hash size={16} /> CALCULATE SHA-256</>}</button></div></div>
    {digest && <div className="panel-card hash-result-card"><div className="hash-result-top"><div className="hash-symbol"><Hash size={20} /></div><div><span className="mini-label">SHA-256 DIGEST</span><h3>Checksum generated</h3></div><span className="result-chip"><Check size={13} /> COMPLETE</span></div><div className="hash-output">{digest}<button className="copy-btn" onClick={() => { navigator.clipboard.writeText(digest).then(() => {}).catch(() => {}); }} aria-label="Copy hash"><Copy size={15} /></button></div><div className="hash-file-info"><span>{file?.name}</span><span>{file ? `${file.size.toLocaleString('id-ID')} bytes` : ''}</span></div><button className="secondary-btn full-width" onClick={() => saveTextFile(`${slugify(file?.name ?? 'file')}-sha256.txt`, `${digest}  ${file?.name ?? ''}\n`)}><Download size={15} /> EXPORT CHECKSUM</button></div>}
  </ToolLayout>;
}

function ResultPanel({ output, onSave, onExport }: { output: OutputState; onSave: () => void; onExport: () => void }) {
  const json = useMemo(() => JSON.stringify(output.data, null, 2), [output.data]);
  const [copied, setCopied] = useState(false);
  function copy() { navigator.clipboard.writeText(json).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1500); }).catch(() => {}); }
  return <section className="panel-card generic-result"><div className="card-heading"><div><span className="mini-label">LATEST RESULT / {output.title.toUpperCase()}</span><h3>{output.subject}</h3></div><span className="result-chip"><span className="status-dot" /> RESULT READY</span></div>{output.note && <p className="result-note"><ShieldCheck size={15} />{output.note}</p>}<div className="result-toolbar"><span><TerminalSquare size={15} /> STRUCTURED OUTPUT / JSON</span><div><button className="secondary-btn small" onClick={copy}>{copied ? <Check size={14} /> : <Copy size={14} />}{copied ? 'COPIED' : 'COPY'}</button><button className="secondary-btn small" onClick={onExport}><Download size={14} /> EXPORT</button><button className="primary-btn small" onClick={onSave}><Database size={14} /> SAVE FINDING</button></div></div><pre className="json-output">{json}</pre><div className="json-footer"><span><span className="status-dot" /> READ-ONLY OUTPUT</span><span>{new Blob([json]).size.toLocaleString('id-ID')} bytes</span></div></section>;
}

function Workspace({ entries, deleteEntry, exportEntries, setFinding, setActiveTool }: { entries: WorkspaceEntry[]; deleteEntry: (id: string) => void; exportEntries: () => void; setFinding: (title: string, subject: string, data: unknown, note?: string) => void; setActiveTool: (id: ToolId) => void }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  function openEntry(entry: WorkspaceEntry) { setFinding(entry.title, entry.subject, entry.data, `Dibuka dari penyimpanan lokal • ${formatDate(entry.createdAt)}`); setActiveTool(entry.type === 'overview' || entry.type === 'workspace' ? 'domain' : entry.type as ToolId); }
  return <>
    <div className="workspace-toolbar panel-card"><div><span className="mini-label">LOCAL-FIRST STORAGE</span><h3>{entries.length} saved finding{entries.length === 1 ? '' : 's'}</h3><p>Data hanya tersedia pada browser dan perangkat tempat hasil disimpan.</p></div><div className="workspace-actions"><button className="secondary-btn" onClick={exportEntries} disabled={!entries.length}><Download size={15} /> EXPORT JSON</button>{entries.length > 0 && <button className="danger-btn" onClick={() => { if (window.confirm('Hapus semua temuan yang tersimpan di browser ini?')) { try { localStorage.removeItem(STORAGE_KEY); } catch {} window.location.reload(); } }}><Trash2 size={15} /> CLEAR ALL</button>}</div></div>
    {entries.length === 0 ? <div className="panel-card workspace-empty"><div className="empty-glyph large"><History size={24} /></div><h3>Your workspace is quiet.</h3><p>Jalankan pemeriksaan dari salah satu tool, lalu pilih <strong>Save finding</strong> untuk menyimpannya.</p><div className="empty-shortcuts"><button className="secondary-btn" onClick={() => setActiveTool('domain')}><Globe2 size={15} /> DOMAIN RECON</button><button className="secondary-btn" onClick={() => setActiveTool('url')}><Link2 size={15} /> URL INSPECTOR</button></div></div> : <div className="saved-findings-list">{entries.map((entry) => <div className="saved-finding panel-card" key={entry.id}><div className="saved-finding-symbol"><FileKey2 size={18} /></div><div className="saved-finding-main"><span className="mini-label">{entry.type.toUpperCase()} / {formatDate(entry.createdAt)}</span><h3>{entry.title}</h3><p>{entry.subject}</p></div><div className="saved-finding-actions"><button className="secondary-btn small" onClick={() => setExpanded(expanded === entry.id ? null : entry.id)}>{expanded === entry.id ? <X size={14} /> : <BookOpen size={14} />}{expanded === entry.id ? 'HIDE' : 'PREVIEW'}</button><button className="secondary-btn small" onClick={() => saveTextFile(`bocil-osint-${slugify(entry.subject)}.json`, JSON.stringify(entry, null, 2), 'application/json;charset=utf-8')}><Download size={14} /></button><button className="icon-btn delete-btn" aria-label="Hapus temuan" onClick={() => deleteEntry(entry.id)}><Trash2 size={15} /></button></div>{expanded === entry.id && <div className="saved-preview"><pre>{JSON.stringify(entry.data, null, 2)}</pre><button className="text-action" onClick={() => openEntry(entry)}>OPEN RESULT <ArrowUpRight size={14} /></button></div>}</div>)}</div>}
    <div className="inline-tip"><LockKeyhole size={16} /><span>Local Storage bukan penyimpanan terenkripsi atau sinkronisasi cloud. Jangan simpan temuan sensitif pada perangkat bersama; ekspor laporan bila perlu membuat salinan.</span></div>
  </>;
}

function SourceCard({ title, items }: { title: string; items: string[] }) { return <div className="panel-card aside-card"><div className="mini-label">REFERENCE</div><h3>{title}</h3><div className="source-items">{items.map((item) => <div key={item}><span className="tiny-check"><Check size={11} /></span>{item}</div>)}</div></div>; }
function NoticeCard({ title, text }: { title: string; text: string }) { return <div className="notice-card"><div className="notice-icon"><Shield size={16} /></div><div><h3>{title}</h3><p>{text}</p></div></div>; }
function Metric({ label, value }: { label: string; value: string }) { return <div className="metric"><span>{label}</span><strong title={value}>{value}</strong></div>; }
function slugify(value: string) { return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 64) || 'finding'; }

export default App;
