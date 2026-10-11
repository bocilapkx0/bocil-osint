export type DnsAnswer = {
  name?: string;
  type?: number;
  TTL?: number;
  data?: string;
};

export type DnsResult = {
  name: string;
  type: string;
  answers: DnsAnswer[];
  status: number;
};

const DNS_TYPES: Record<number, string> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  12: 'PTR',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  33: 'SRV',
  257: 'CAA',
};

export function cleanDomain(input: string): string {
  let value = input.trim().toLowerCase();
  value = value.replace(/^https?:\/\//, '').split(/[/?#]/)[0] ?? '';
  value = value.replace(/:\d+$/, '').replace(/\.$/, '');
  return value;
}

export function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253 || !domain.includes('.')) return false;
  if (/^\d+(\.\d+){3}$/.test(domain)) return false;
  return domain.split('.').every((label) =>
    label.length >= 1 && label.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
  );
}

export function isIPv4(value: string): boolean {
  const parts = value.trim().split('.');
  return parts.length === 4 && parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const number = Number(part);
    return number >= 0 && number <= 255;
  });
}

export function isIPv6(value: string): boolean {
  return value.includes(':') && /^[0-9a-f:]+$/i.test(value) && value.split(':').length >= 3;
}

export function detectInputKind(input: string): 'url' | 'ip' | 'domain' | 'unknown' {
  const value = input.trim();
  if (!value) return 'unknown';
  if (/^https?:\/\//i.test(value) || value.includes('/') || value.includes('?')) return 'url';
  if (isIPv4(value) || isIPv6(value)) return 'ip';
  if (isValidDomain(cleanDomain(value))) return 'domain';
  return 'unknown';
}

export async function queryDns(name: string, type: string): Promise<DnsResult> {
  const params = new URLSearchParams({ name, type });
  const response = await fetch(`https://dns.google/resolve?${params.toString()}`, {
    headers: { Accept: 'application/dns-json' },
  });
  if (!response.ok) throw new Error(`DNS-over-HTTPS tidak tersedia (HTTP ${response.status}).`);
  const data = await response.json() as { Status?: number; Answer?: DnsAnswer[]; Question?: { name: string }[] };
  return {
    name: data.Question?.[0]?.name ?? name,
    type,
    answers: data.Answer ?? [],
    status: data.Status ?? -1,
  };
}

export async function getDomainDns(domain: string): Promise<DnsResult[]> {
  const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA'];
  const results = await Promise.all(types.map(async (type) => {
    try {
      return await queryDns(domain, type);
    } catch {
      return { name: domain, type, answers: [], status: -1 };
    }
  }));
  return results;
}

export function dnsTypeName(type?: number): string {
  return type ? DNS_TYPES[type] ?? String(type) : 'UNKNOWN';
}

export async function getRdapDomain(domain: string): Promise<Record<string, unknown>> {
  const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
    headers: { Accept: 'application/rdap+json, application/json' },
  });
  if (!response.ok) throw new Error(`Data RDAP domain tidak tersedia (HTTP ${response.status}).`);
  return await response.json() as Record<string, unknown>;
}

export async function getIpInfo(ip: string): Promise<Record<string, unknown>> {
  const response = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`);
  if (!response.ok) throw new Error(`Layanan IP intelligence tidak tersedia (HTTP ${response.status}).`);
  const data = await response.json() as Record<string, unknown>;
  if (data.success === false) throw new Error(String(data.message ?? 'Alamat IP tidak dapat diperiksa.'));
  return data;
}

export function inspectUrl(input: string) {
  let url: URL;
  try {
    url = new URL(input.trim().includes('://') ? input.trim() : `https://${input.trim()}`);
  } catch {
    throw new Error('URL belum valid. Masukkan domain atau URL lengkap.');
  }
  const host = url.hostname.toLowerCase();
  const flags: { title: string; detail: string; level: 'high' | 'medium' | 'info' }[] = [];
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'ow.ly', 'rb.gy'];
  const suspiciousWords = ['login', 'verify', 'secure', 'account', 'password', 'wallet', 'gift', 'claim', 'update'];
  const isIp = isIPv4(host) || isIPv6(host);

  if (url.protocol !== 'https:') flags.push({ title: 'Tidak memakai HTTPS', detail: 'Koneksi memakai HTTP atau skema lain. Ini bukan bukti penipuan, tetapi data yang dikirim mungkin tidak terenkripsi.', level: 'medium' });
  if (url.username || url.password || input.includes('@')) flags.push({ title: 'Terdapat pola kredensial / simbol @', detail: 'Periksa hostname sebenarnya. Simbol @ pada URL bisa dipakai untuk menyamarkan tujuan tautan.', level: 'high' });
  if (isIp) flags.push({ title: 'Hostname berupa alamat IP', detail: 'Alamat IP langsung tidak selalu berbahaya, tetapi patut diperiksa jika dikirim sebagai tautan login.', level: 'medium' });
  if (host.startsWith('xn--') || host.split('.').some((part) => part.startsWith('xn--'))) flags.push({ title: 'Hostname memakai punycode', detail: 'Nama domain internasional dapat memakai karakter yang mirip dengan huruf lain. Pastikan ejaan domain benar.', level: 'medium' });
  if (shorteners.includes(host)) flags.push({ title: 'Layanan pemendek tautan', detail: 'Tujuan akhir tidak terlihat dari URL ini saja. Buka hanya melalui pemeriksa pengalihan tepercaya.', level: 'medium' });
  if (suspiciousWords.some((word) => `${host}${url.pathname}`.toLowerCase().includes(word))) flags.push({ title: 'Kata yang sering muncul pada umpan login', detail: 'Kata ini juga bisa muncul pada situs sah. Perlakukan sebagai sinyal lemah, bukan kesimpulan.', level: 'medium' });
  if (host.split('.').length >= 5) flags.push({ title: 'Subdomain cukup panjang', detail: 'Pastikan domain registrabel yang sebenarnya, bukan hanya bagian awal hostname.', level: 'medium' });
  if (url.href.length > 180) flags.push({ title: 'URL sangat panjang', detail: 'Tautan panjang dapat sah, namun parameter berlebih dapat menyulitkan pemeriksaan tujuan.', level: 'info' });
  if (url.search) flags.push({ title: 'Memiliki parameter query', detail: `${new URLSearchParams(url.search).size} parameter query terdeteksi. Jangan bagikan URL yang mungkin mengandung token rahasia.`, level: 'info' });
  if (flags.length === 0) flags.push({ title: 'Tidak ada indikator sederhana yang terdeteksi', detail: 'Analisis lokal ini bukan pemindai reputasi dan tidak menjamin URL aman.', level: 'info' });

  const score = Math.min(100, flags.reduce((sum, flag) => sum + (flag.level === 'high' ? 35 : flag.level === 'medium' ? 16 : 4), 0));
  const risk = score >= 50 ? 'Perlu perhatian tinggi' : score >= 20 ? 'Perlu ditinjau' : 'Indikator terbatas';
  return {
    url: url.href,
    protocol: url.protocol,
    hostname: host,
    port: url.port || (url.protocol === 'https:' ? '443 (default)' : '80 (default)'),
    path: url.pathname || '/',
    queryParameterCount: new URLSearchParams(url.search).size,
    fragmentPresent: Boolean(url.hash),
    score,
    risk,
    flags,
    analyzedAt: new Date().toISOString(),
    method: 'Analisis URL lokal di browser; tidak melakukan request ke URL target.',
  };
}

export function checkEmailSyntax(input: string): { email: string; domain: string; valid: boolean; reason: string } {
  const email = input.trim();
  const basic = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(email) && email.length <= 254;
  const domain = email.split('@').pop()?.toLowerCase() ?? '';
  if (!basic) return { email, domain, valid: false, reason: 'Format email tidak sesuai pemeriksaan sintaks dasar.' };
  if (!isValidDomain(domain)) return { email, domain, valid: false, reason: 'Bagian domain email tidak valid.' };
  return { email, domain, valid: true, reason: 'Format terlihat valid. Ini belum membuktikan kotak email ada atau dapat menerima pesan.' };
}

export function summarizeRdap(data: Record<string, unknown>) {
  const events = Array.isArray(data.events) ? data.events as Record<string, unknown>[] : [];
  const nameservers = Array.isArray(data.nameservers) ? data.nameservers as Record<string, unknown>[] : [];
  const statuses = Array.isArray(data.status) ? data.status as string[] : [];
  const entities = Array.isArray(data.entities) ? data.entities as Record<string, unknown>[] : [];
  return {
    domain: data.ldhName ?? data.unicodeName ?? '—',
    handle: data.handle ?? '—',
    status: statuses,
    nameservers: nameservers.map((ns) => ns.ldhName ?? ns.unicodeName ?? '—'),
    events: events.map((event) => ({ action: event.eventAction, date: event.eventDate })),
    entities: entities.map((entity) => ({ roles: entity.roles, handle: entity.handle ?? '—' })),
    secureDNS: data.secureDNS ?? null,
    notices: Array.isArray(data.notices) ? data.notices.map((notice: unknown) => {
      const entry = notice as Record<string, unknown>;
      return { title: entry.title, description: entry.description };
    }) : [],
  };
}

export function saveTextFile(filename: string, content: string, mime = 'text/plain;charset=utf-8') {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function formatDate(value: string | number | Date) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat('id-ID', { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}
