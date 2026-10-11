import { isIP } from 'node:net';

const RATE_WINDOW_MS = 60_000;
const RATE_MAX = 12;
const CACHE_SECONDS = 600;

// Best-effort per-runtime guard. Serverless instances are ephemeral, so this is not a durable global rate limiter.
const buckets = globalThis.__bocilCensysBuckets ?? new Map();
globalThis.__bocilCensysBuckets = buckets;

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'x-content-type-options': 'nosniff',
      'cache-control': 'no-store',
      ...extraHeaders,
    },
  });
}

function clientKey(request) {
  // Vercel supplies these headers; this is an abuse-throttling hint, not an authentication identity.
  const forwarded = request.headers.get('x-forwarded-for');
  const realIp = request.headers.get('x-real-ip');
  const address = (forwarded ? forwarded.split(',').at(-1) : realIp) ?? 'unknown';
  return address.trim().slice(0, 80) || 'unknown';
}

function consumeRateLimit(key) {
  const now = Date.now();
  const recent = (buckets.get(key) ?? []).filter((time) => now - time < RATE_WINDOW_MS);
  if (recent.length >= RATE_MAX) {
    buckets.set(key, recent);
    return false;
  }
  recent.push(now);
  buckets.set(key, recent);
  if (buckets.size > 1000) {
    for (const [entryKey, times] of buckets.entries()) {
      if (!times.some((time) => now - time < RATE_WINDOW_MS)) buckets.delete(entryKey);
    }
  }
  return true;
}

function isPublicIp(value) {
  const family = isIP(value);
  if (family === 4) {
    const [a, b, c] = value.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false; // Shared address space (100.64/10)
    if (a === 169 && b === 254) return false; // Link-local
    if (a === 172 && b >= 16 && b <= 31) return false; // Private
    if (a === 192 && b === 168) return false; // Private
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return false; // IETF special-purpose / documentation
    if (a === 192 && b === 88 && c === 99) return false; // Deprecated 6to4 relay
    if (a === 198 && (b === 18 || b === 19)) return false; // Benchmarking
    if (a === 198 && b === 51 && c === 100) return false; // Documentation
    if (a === 203 && b === 0 && c === 113) return false; // Documentation
    return true;
  }
  if (family === 6) {
    const lower = value.toLowerCase();
    const firstWord = Number.parseInt(lower.split(':')[0] || '0', 16);
    // Restrict to global-unicast space (2000::/3); excludes loopback, link-local,
    // unique-local, multicast and IPv4-mapped IPv6 forms.
    if (firstWord < 0x2000 || firstWord > 0x3fff) return false;
    if (lower.startsWith('2001:db8:')) return false; // Documentation range
    return true;
  }
  return false;
}

function normalizeLookup(type, raw) {
  const query = String(raw ?? '').trim();
  if (!query || query.length > 512) throw new Error('Masukkan nilai lookup yang valid.');
  if (type === 'host') {
    if (query.length > 45 || !isPublicIp(query)) throw new Error('Lookup host hanya menerima alamat IP publik IPv4/IPv6 yang valid. IP privat atau khusus ditolak.');
    return { query, path: `/v3/global/asset/host/${encodeURIComponent(query)}`, accept: 'application/vnd.censys.api.v3.host.v1+json, application/json' };
  }
  if (type === 'webproperty') {
    const separator = query.lastIndexOf(':');
    const hostname = separator > 0 ? query.slice(0, separator).toLowerCase() : '';
    const portText = separator > 0 ? query.slice(separator + 1) : '';
    const port = Number(portText);
    const isValidHostname = isIP(hostname) === 4 || (hostname.length <= 253 && hostname.includes('.') && hostname.split('.').every((label) => label.length >= 1 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)));
    if (!isValidHostname || !/^\d{1,5}$/.test(portText) || !Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error('Web property harus berupa hostname:port, misalnya example.com:443. IPv6 web property belum didukung di formulir ini.');
    }
    const normalized = `${hostname}:${port}`;
    return { query: normalized, path: `/v3/global/asset/webproperty/${encodeURIComponent(normalized)}`, accept: 'application/vnd.censys.api.v3.webproperty.v1+json, application/json' };
  }
  if (type === 'certificate') {
    const fingerprint = query.replace(/:/g, '').toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(fingerprint)) throw new Error('Fingerprint sertifikat harus berisi tepat 64 karakter heksadesimal SHA-256.');
    return { query: fingerprint, path: `/v3/global/asset/certificate/${encodeURIComponent(fingerprint)}`, accept: 'application/vnd.censys.api.v3.certificate.v1+json, application/json' };
  }
  throw new Error('Jenis lookup tidak didukung.');
}

export default {
  async fetch(request) {
    if (request.method !== 'GET') return json({ error: 'Metode tidak didukung. Gunakan GET.' }, 405, { allow: 'GET' });

    const url = new URL(request.url);
    const origin = request.headers.get('origin');
    if (origin) {
      try {
        if (new URL(origin).origin !== url.origin) return json({ error: 'Origin tidak diizinkan.' }, 403);
      } catch {
        return json({ error: 'Header origin tidak valid.' }, 403);
      }
    }

    let normalized;
    const type = url.searchParams.get('type') ?? 'host';
    try {
      normalized = normalizeLookup(type, url.searchParams.get('query'));
    } catch (error) {
      return json({ error: error instanceof Error ? error.message : 'Parameter lookup tidak valid.' }, 400);
    }

    if (!consumeRateLimit(clientKey(request))) {
      return json({ error: 'Terlalu banyak permintaan dalam waktu singkat. Tunggu satu menit lalu coba lagi.' }, 429, { 'retry-after': '60' });
    }

    const token = process.env.CENSYS_API_TOKEN;
    if (!token) {
      return json({ error: 'Censys belum dikonfigurasi di server. Tambahkan CENSYS_API_TOKEN sebagai Secret di pengaturan Vercel lalu deploy ulang.' }, 503);
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    let upstream;
    try {
      upstream = await fetch(`https://api.platform.censys.io${normalized.path}`, {
        method: 'GET',
        headers: { authorization: `Bearer ${token}`, accept: normalized.accept },
        signal: controller.signal,
      });
    } catch (error) {
      const timedOut = error?.name === 'AbortError';
      return json({ error: timedOut ? 'Censys tidak merespons dalam 10 detik. Coba lagi nanti.' : 'Tidak dapat menghubungi Censys. Periksa koneksi layanan.' }, timedOut ? 504 : 502);
    } finally {
      clearTimeout(timeout);
    }

    if (upstream.status === 404) return json({ error: 'Censys tidak menemukan rekaman untuk identifier tersebut.' }, 404);
    if (upstream.status === 401) return json({ error: 'Censys menolak token. Periksa token server dan pastikan token lama yang terekspos sudah dicabut.' }, 502);
    if (upstream.status === 403) return json({ error: 'Akun atau token Censys tidak memiliki izin untuk endpoint ini.' }, 403);
    if (upstream.status === 429) return json({ error: 'Batas permintaan atau kredit API Censys tercapai. Periksa kuota dan rate limit akun Censys.' }, 429, { 'retry-after': '60' });
    if (!upstream.ok) return json({ error: `Censys mengembalikan kesalahan HTTP ${upstream.status}.` }, 502);

    let result;
    try { result = await upstream.json(); }
    catch { return json({ error: 'Respons Censys bukan JSON yang valid.' }, 502); }

    return json({ provider: 'Censys Platform API v3', lookupType: type, query: normalized.query, retrievedAt: new Date().toISOString(), result }, 200, {
      'cache-control': `public, s-maxage=${CACHE_SECONDS}, stale-while-revalidate=1800`,
    });
  },
};
