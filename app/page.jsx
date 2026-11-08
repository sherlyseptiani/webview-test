/*
  ============================================================================
  TEST / DISPLAY-ONLY SECURITY EVIDENCE PAGE  —  NO EXFILTRATION.
  ----------------------------------------------------------------------------
  This page is on-screen evidence for an authorized internal security review.
  It works in both Android (addJavascriptInterface) and iOS (WKWebView
  webkit.messageHandlers) WebViews.
  It performs ZERO network activity (no fetch / XHR / WebSocket / sendBeacon /
  form submit / redirect / image or script beacon) and persists NOTHING.
  Every secret is truncated before display (first 6 + last 4, middle elided).
  Exactly one live native-bridge method is invoked (REFRESH_ACCESS_TOKEN),
  once, with no retry or loop. No getUserMedia is ever called — only
  enumerateDevices() for labels. Every probe is wrapped in try/catch so a
  single failure cannot blank the page.
  ============================================================================
*/
'use client';

import { useEffect, useRef, useState } from 'react';

// --- Static catalog. Display-only. These are intentionally NOT invoked. ------
const BRIDGE_METHODS = [
  ['REFRESH_ACCESS_TOKEN', 'Session', 'returns fresh access token (demonstrated live above)'],
  ['REFRESH_PIN_TOKEN', 'Session', 'returns/refreshes PIN token'],
  ['REPLACE_NATIVE_TOKEN', 'Session', 'overwrites stored session — do NOT call'],
  ['SIGN', 'Signing', 'capability unreviewed — do NOT call'],
  ['SIGN_SIGNATURE', 'Signing', 'capability unreviewed — do NOT call'],
  ['DOWNLOAD_RESOURCE', 'File', 'do NOT call'],
  ['DOWNLOAD_BASE64', 'File', 'filename traversal risk — do NOT call'],
  ['DOWNLOAD_URL', 'File', 'do NOT call'],
  ['COPY_TO_CLIPBOARD', 'File', ''],
  ['DEEPLINK', 'Nav', 'launches internal app routes'],
  ['IN_APP_BROWSER', 'Nav', ''],
  ['EXTERNAL_BROWSER', 'Nav', ''],
  ['BOTTOM_SHEET', 'Nav', ''],
  ['CLOSE_WEBVIEW', 'Nav', ''],
  ['SCREEN_ORIENTATION', 'Nav', ''],
  ['GET_LOCATION', 'Sensor', 'device location'],
  ['REQUEST_PERMISSION', 'Sensor', ''],
  ['VIBRATE', 'Sensor', ''],
  ['AUDIO', 'Sensor', ''],
  ['KYC_OPEN_CAMERA', 'KYC', 'camera + identity documents'],
  ['KYC_START_LIVENESS', 'KYC', ''],
  ['KYC_OPEN_VIDEO_SELFIE', 'KYC', ''],
  ['KYC_PHOTO_SELFIE_SUBMISSION', 'KYC', ''],
  ['KYC_COMPLETE_PROCESS', 'KYC', ''],
  ['PHONE_VERIFICATION', 'Identity', ''],
  ['OPEN_WHATSAPP', 'Comms', ''],
  ['OPEN_EMAIL', 'Comms', ''],
  ['GET_METADATA', 'Data', ''],
  ['UPDATE_METADATA', 'Data', ''],
  ['SEND_METADATA', 'Data', ''],
  ['ANALYTICS', 'Analytics', ''],
];

const HIGHLIGHT = ['ACCESS_TOKEN', 'X_DEVICE_SIGNATURE', 'HASHED_EMAIL'];
const VERSION_COOKIE_KEYS = ['app_version', 'APP_VERSION', 'appVersion', 'version', 'VERSION'];

// Entry-point objects we check by name, with the method names we expect to see.
// Reflection reveals the real exposed methods live; the heuristic scan below
// catches any additional injected interface we did not name here.
const KNOWN_BRIDGE_GLOBALS = [
  { name: 'Android', expect: ['callHandler'] },
  { name: 'ajaib', expect: ['webEvent'] },
  { name: 'AndroidBridge', expect: [] },
  { name: 'NativeBridge', expect: [] },
  { name: 'AndroidInterface', expect: [] },
  { name: 'JSBridge', expect: [] },
];

// iOS WKWebView exposes message handlers under window.webkit.messageHandlers.
// That object is not enumerable, so we probe known handler names by presence
// (reading messageHandlers[name] returns the handler; it does NOT post a
// message). Extend this list with the app's real handler names.
const IOS_HANDLER_CANDIDATES = [
  'callHandler',
  'ajaib',
  'bridge',
  'nativeBridge',
  'jsBridge',
  'JSBridge',
  'postMessage',
  'observe',
];

// Standard globals that would otherwise match the "only function members"
// signature and create noise. The signature already excludes most of window.
const SCAN_DENYLIST = new Set([
  'JSON', 'Math', 'Reflect', 'Atomics', 'console', 'crypto', 'Intl', 'WebAssembly',
  'Promise', 'Proxy', 'Array', 'Object', 'Function', 'String', 'Number', 'Boolean',
  'Symbol', 'BigInt', 'Date', 'RegExp', 'Error', 'Map', 'Set', 'WeakMap', 'WeakSet',
  'localStorage', 'sessionStorage', 'navigator', 'document', 'location', 'history',
  'window', 'self', 'globalThis', 'frames', 'top', 'parent', 'chrome', 'external',
]);

// Show only first 6 + last 4 chars; elide the middle. Short values are fully
// hidden so we never reveal a secret that is too short to truncate meaningfully.
function truncateSecret(value) {
  try {
    if (value == null) return '';
    const s = String(value);
    if (s.length === 0) return '(empty)';
    if (s.length <= 12) return '…'.repeat(Math.min(s.length, 6));
    return s.slice(0, 6) + '…' + s.slice(-4);
  } catch {
    return '…';
  }
}

function readCookies() {
  try {
    const raw = typeof document !== 'undefined' ? document.cookie || '' : '';
    if (!raw) return [];
    return raw
      .split(';')
      .map((pair) => {
        const idx = pair.indexOf('=');
        const name = (idx >= 0 ? pair.slice(0, idx) : pair).trim();
        const value = idx >= 0 ? pair.slice(idx + 1).trim() : '';
        return { name, value };
      })
      .filter((c) => c.name);
  } catch {
    return [];
  }
}

// Injected Android interface objects expose ONLY Java methods as own properties.
// Treat an object whose every own property is a function as a candidate bridge.
function looksLikeInterface(val) {
  try {
    if (val == null) return false;
    const t = typeof val;
    if (t !== 'object' && t !== 'function') return false;
    const props = Object.getOwnPropertyNames(val);
    if (props.length === 0) return false;
    for (const p of props) {
      let kind;
      try {
        kind = typeof val[p];
      } catch {
        return false;
      }
      if (kind !== 'function') return false;
    }
    return true;
  } catch {
    return false;
  }
}

// Discover injected bridge objects live. Reflection of method names only —
// no bridge method is ever invoked here.
function discoverBridges() {
  const known = [];
  const seen = new Set();

  for (const cand of KNOWN_BRIDGE_GLOBALS) {
    seen.add(cand.name);
    try {
      const obj = typeof window !== 'undefined' ? window[cand.name] : null;
      const present = obj != null && (typeof obj === 'object' || typeof obj === 'function');
      known.push({
        name: cand.name,
        expect: cand.expect,
        names: present ? Object.getOwnPropertyNames(obj) : [],
        error: null,
      });
    } catch (e) {
      known.push({ name: cand.name, expect: cand.expect, names: [], error: String(e && e.message ? e.message : e) });
    }
  }

  // Heuristic: any other window property that looks like an injected interface.
  const extra = [];
  try {
    for (const name of Object.getOwnPropertyNames(window)) {
      if (seen.has(name) || SCAN_DENYLIST.has(name)) continue;
      let val;
      try {
        val = window[name];
      } catch {
        continue; // some window getters throw; skip them
      }
      if (looksLikeInterface(val)) {
        try {
          extra.push({ name, names: Object.getOwnPropertyNames(val) });
        } catch {
          /* ignore */
        }
      }
    }
  } catch {
    /* ignore */
  }

  return { known, extra, ios: discoverIosHandlers() };
}

// iOS WKWebView message handlers. messageHandlers is not enumerable, so we probe
// candidate names by presence only. Reading messageHandlers[name] returns the
// handler object; it does NOT send a message.
function discoverIosHandlers() {
  try {
    const wk = typeof window !== 'undefined' ? window.webkit : null;
    const mh = wk && wk.messageHandlers;
    if (!mh) return { present: false, handlers: [], error: null };
    const handlers = [];
    for (const name of IOS_HANDLER_CANDIDATES) {
      try {
        const h = mh[name];
        if (h && typeof h.postMessage === 'function') handlers.push(name);
      } catch {
        /* ignore individual handler probe */
      }
    }
    return { present: true, handlers, error: null };
  } catch (e) {
    return { present: false, handlers: [], error: String(e && e.message ? e.message : e) };
  }
}

// Best-effort runtime label for the report.
function detectPlatform() {
  try {
    const ua = (typeof navigator !== 'undefined' && navigator.userAgent) || '';
    const hasAndroid =
      typeof window !== 'undefined' && window.Android && typeof window.Android.callHandler === 'function';
    const hasWk = typeof window !== 'undefined' && window.webkit && window.webkit.messageHandlers;
    const bits = [];
    if (hasAndroid) bits.push('Android JS interface');
    if (hasWk) bits.push('iOS WKWebView message handlers');
    const os = /iPhone|iPad|iPod/i.test(ua)
      ? 'iOS'
      : /Android/i.test(ua)
      ? 'Android'
      : 'other/desktop';
    return `${os}${bits.length ? ' — ' + bits.join(' + ') : ' — no native bridge detected'}`;
  } catch {
    return '(unknown)';
  }
}

export default function Page() {
  const [host, setHost] = useState('');
  const [href, setHref] = useState('');
  const [cookies, setCookies] = useState([]);
  const [bridges, setBridges] = useState({ known: [], extra: [], ios: { present: false, handlers: [] } });
  const [platform, setPlatform] = useState('');
  const [tokenResult, setTokenResult] = useState({ status: 'pending', token: null });
  const [mediaDevices, setMediaDevices] = useState(null);
  const [mediaError, setMediaError] = useState(null);
  const [stamp, setStamp] = useState('');
  const [appVersion, setAppVersion] = useState('(not found in cookies)');

  const tokenProbed = useRef(false); // guard: REFRESH_ACCESS_TOKEN runs at most once

  useEffect(() => {
    // --- Location banner ---
    try {
      setHost(window.location.hostname);
      setHref(window.location.href);
    } catch {
      /* ignore */
    }

    // --- Cookies ---
    const parsed = readCookies();
    setCookies(parsed);
    try {
      const vk = parsed.find((c) => VERSION_COOKIE_KEYS.includes(c.name));
      if (vk) setAppVersion(vk.value || '(empty)');
    } catch {
      /* ignore */
    }

    // --- Bridge reflection (names only; no invocation) ---
    try {
      setBridges(discoverBridges());
    } catch {
      setBridges({ known: [], extra: [], ios: { present: false, handlers: [] } });
    }

    // --- Platform / runtime label ---
    try {
      setPlatform(detectPlatform());
    } catch {
      /* ignore */
    }

    // --- Timestamp for the report ---
    try {
      setStamp(new Date().toString());
    } catch {
      /* ignore */
    }

    // --- Live token probe: exactly one call, no retry, no loop ---
    // Works on Android (callHandler) and iOS (webkit.messageHandlers.postMessage).
    if (!tokenProbed.current) {
      tokenProbed.current = true;
      try {
        probeRefreshToken(setTokenResult);
      } catch (e) {
        setTokenResult({ status: 'error', token: null, error: String(e && e.message ? e.message : e) });
      }
    }

    // --- Media reach: enumerateDevices only. getUserMedia is NEVER called. ---
    try {
      if (!navigator.mediaDevices || typeof navigator.mediaDevices.enumerateDevices !== 'function') {
        setMediaError('navigator.mediaDevices.enumerateDevices is unavailable');
      } else {
        // A single enumerate; result maps to kind + label for display only.
        navigator.mediaDevices
          .enumerateDevices()
          .then((devices) => {
            try {
              setMediaDevices(
                devices.map((d) => ({
                  kind: d.kind,
                  label: d.label || '(label withheld until permission granted)',
                })),
              );
            } catch (e) {
              setMediaError(String(e && e.message ? e.message : e));
            }
          })
          .catch((e) => setMediaError(String(e && e.message ? e.message : e)));
      }
    } catch (e) {
      setMediaError(String(e && e.message ? e.message : e));
    }
  }, []);

  return (
    <main className="wrap">
      <div className="disclaimer">
        Test / display-only security evidence. No network activity, no storage, no exfiltration.
        Secrets are truncated. One bridge method is invoked once; all others are listed only.
      </div>

      {/* Banner */}
      <section className="banner">
        <h1>Webview Test Page</h1>
        <div className="kv">
          <span className="k">location.hostname</span> = {host || '(unknown)'}
        </div>
        <div className="kv">
          <span className="k">location.href</span> = {href || '(unknown)'}
        </div>
        <div className="kv">
          <span className="k">detected runtime</span> = {platform || '(detecting…)'}
        </div>
      </section>

      {/* Cookies */}
      <CookiesCard cookies={cookies} />

      {/* Bridge entry points — live reflection */}
      <section className="card risk">
        <h2>Bridge entry points (live reflection)</h2>
        <p className="label">
          These objects are injected into this untrusted origin. Discovered live from the actual
          bridge; method names are reflected, never invoked.
        </p>
        {bridges.known.map((b) => (
          <ReflectionRow key={b.name} bridge={b} />
        ))}
        {bridges.extra && bridges.extra.length > 0 ? (
          <div style={{ marginTop: 8 }}>
            <div className="expect" style={{ marginBottom: 6 }}>
              heuristic: other window objects exposing only method members (possible additional
              injected interfaces)
            </div>
            {bridges.extra.map((b) => (
              <div key={b.name} style={{ marginBottom: 8 }}>
                <div
                  style={{ fontFamily: 'var(--mono)', fontSize: 12.5, marginBottom: 4, wordBreak: 'break-all' }}
                >
                  window.{b.name}
                </div>
                <div>
                  {b.names.map((n) => (
                    <span className="chip" key={n}>
                      {n}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : null}
        {bridges.ios && bridges.ios.present ? (
          <div style={{ marginTop: 8 }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 12.5, marginBottom: 6, wordBreak: 'break-all' }}>
              window.webkit.messageHandlers (iOS WKWebView)
            </div>
            {bridges.ios.handlers.length > 0 ? (
              <div>
                {bridges.ios.handlers.map((n) => (
                  <span className="chip" key={n}>
                    {n}
                  </span>
                ))}
              </div>
            ) : (
              <div className="note">
                present, but no candidate handler names matched (handlers are not enumerable — add
                the app&apos;s real handler names to probe them)
              </div>
            )}
            <div className="expect">probed by name; message handlers cannot be enumerated from JS</div>
          </div>
        ) : null}
      </section>

      {/* Live token probe */}
      <section className="card risk">
        <h2>Live token probe</h2>
        <p className="label">The native bridge actively hands a fresh token to this page.</p>
        <p className="note" style={{ marginTop: 0 }}>
          One call to the native bridge — Android <code>callHandler</code> or iOS{' '}
          <code>webkit.messageHandlers.*.postMessage</code> — with{' '}
          <code>{'{"method":"REFRESH_ACCESS_TOKEN"}'}</code>. No retry, no loop.
        </p>
        <div className="row">
          <span className="name">status</span>
          <span className="val">
            <TokenStatus status={tokenResult.status} />
          </span>
        </div>
        {tokenResult.via ? (
          <div className="row">
            <span className="name">via</span>
            <span className="val">{tokenResult.via}</span>
          </div>
        ) : null}
        <div className="row">
          <span className="name">access token (truncated)</span>
          <span className="val">{tokenResult.token ? truncateSecret(tokenResult.token) : '—'}</span>
        </div>
        {tokenResult.error ? (
          <div className="row">
            <span className="name">detail</span>
            <span className="val">{tokenResult.error}</span>
          </div>
        ) : null}
      </section>

      {/* Media reach */}
      <section className="card">
        <h2>Media reach</h2>
        <p className="label">
          Camera/microphone are reachable to this origin (reach, not recording, is the point).
        </p>
        {mediaError ? (
          <div className="note">enumerateDevices unavailable: {mediaError}</div>
        ) : mediaDevices == null ? (
          <div className="note">probing…</div>
        ) : mediaDevices.length === 0 ? (
          <div className="note">No devices reported.</div>
        ) : (
          mediaDevices.map((d, i) => (
            <div className="row" key={i}>
              <span className="name">{d.kind}</span>
              <span className="val">{d.label}</span>
            </div>
          ))
        )}
      </section>

      {/* Bridge dispatch catalog — static, display-only */}
      <section className="card">
        <h2>Bridge dispatch catalog</h2>
        <p className="label">
          Dispatch targets of the native bridge (Android <code>callHandler</code> / iOS message
          handler). This page can reach any of them; listed for evidence and intentionally NOT
          invoked.
        </p>
        <div style={{ overflowX: 'auto' }}>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Category</th>
              </tr>
            </thead>
            <tbody>
              {BRIDGE_METHODS.map(([name, category]) => (
                <tr key={name} className={`cat-${category}`}>
                  <td className="name">{name}</td>
                  <td>
                    <span className="cat-tag">{category}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Footer */}
      <footer className="footer">
        <div>report generated: {stamp || '(unknown)'}</div>
        <div>app version: {appVersion}</div>
      </footer>
    </main>
  );
}

// Invoke REFRESH_ACCESS_TOKEN exactly once across platforms. Android uses the
// injected callHandler; iOS posts to the first present WKWebView message handler.
// Only ONE native call is made, with no retry and no loop.
function probeRefreshToken(setTokenResult) {
  const message = JSON.stringify({ method: 'REFRESH_ACCESS_TOKEN', data: {} });

  // 1) Android (or any injected object exposing a callHandler-style function).
  const injected =
    (typeof window !== 'undefined' && window.Android) ||
    (typeof window !== 'undefined' && window.ajaib) ||
    null;
  if (injected && typeof injected.callHandler === 'function') {
    const raw = injected.callHandler(message); // the single live call
    handleTokenReturn(raw, setTokenResult, 'Android callHandler');
    return;
  }

  // 2) iOS WKWebView: post once to the first present candidate handler.
  try {
    const mh =
      typeof window !== 'undefined' && window.webkit ? window.webkit.messageHandlers : null;
    if (mh) {
      for (const name of IOS_HANDLER_CANDIDATES) {
        let h = null;
        try {
          h = mh[name];
        } catch {
          continue;
        }
        if (h && typeof h.postMessage === 'function') {
          // postMessage returns a Promise in modern WKWebView when the native
          // side uses a reply handler; handleTokenReturn handles both.
          const raw = h.postMessage({ method: 'REFRESH_ACCESS_TOKEN', data: {} });
          handleTokenReturn(raw, setTokenResult, 'iOS webkit.messageHandlers.' + name);
          return;
        }
      }
    }
  } catch (e) {
    setTokenResult({ status: 'error', token: null, error: String(e && e.message ? e.message : e) });
    return;
  }

  setTokenResult({ status: 'bridge-unavailable', token: null });
}

// Interpret the one bridge return value. Accepts a string, an object, or a
// single thenable — attaches exactly one .then, never polls.
function handleTokenReturn(raw, setTokenResult, via) {
  try {
    if (raw && typeof raw.then === 'function') {
      raw
        .then((v) => setTokenResult({ ...parseTokenPayload(v), via }))
        .catch((e) =>
          setTokenResult({ status: 'error', token: null, via, error: String(e && e.message ? e.message : e) }),
        );
      return;
    }
    setTokenResult({ ...parseTokenPayload(raw), via });
  } catch (e) {
    setTokenResult({ status: 'error', token: null, via, error: String(e && e.message ? e.message : e) });
  }
}

function parseTokenPayload(raw) {
  try {
    if (raw == null) return { status: 'no-response', token: null };
    let obj = raw;
    if (typeof raw === 'string') {
      try {
        obj = JSON.parse(raw);
      } catch {
        // Non-JSON string: treat the string itself as the token material.
        return { status: 'ok', token: raw };
      }
    }
    if (obj && typeof obj === 'object') {
      const token =
        obj.accessToken || obj.access_token || obj.token || obj.ACCESS_TOKEN || null;
      const status = obj.status || (token ? 'ok' : 'no-token');
      return { status: String(status), token: token ? String(token) : null };
    }
    return { status: 'ok', token: String(obj) };
  } catch (e) {
    return { status: 'error', token: null, error: String(e && e.message ? e.message : e) };
  }
}

function TokenStatus({ status }) {
  const ok = status === 'ok';
  const neutral = status === 'pending' || status === 'bridge-unavailable';
  if (neutral) return <span>{status}</span>;
  return <span className={ok ? 'status-bad' : ''}>{status}</span>;
}

function CookiesCard({ cookies }) {
  const hasAccessToken = cookies.some((c) => c.name === 'ACCESS_TOKEN');
  const isRisk = hasAccessToken || cookies.some((c) => HIGHLIGHT.includes(c.name));
  return (
    <section className={`card${isRisk ? ' risk' : ''}`}>
      <h2>Cookies readable from this origin</h2>
      <p className="label">document.cookie, parsed. Values truncated.</p>
      {cookies.length === 0 ? (
        <div className="note">No cookies readable via document.cookie (HttpOnly cookies are not exposed here).</div>
      ) : (
        cookies.map((c, i) => {
          const flag = HIGHLIGHT.includes(c.name);
          return (
            <div className={`row${flag ? ' flag' : ''}`} key={`${c.name}-${i}`}>
              <span className="name">{c.name}</span>
              <span className="val">{truncateSecret(c.value)}</span>
            </div>
          );
        })
      )}
      {hasAccessToken ? (
        <div className="alert">Session token exposed to third-party host.</div>
      ) : null}
    </section>
  );
}

function ReflectionRow({ bridge }) {
  const names = bridge && bridge.names ? bridge.names : [];
  const expect = bridge && bridge.expect ? bridge.expect : [];
  const err = bridge && bridge.error ? bridge.error : null;
  const matches = expect.length > 0 && names.length > 0 && expect.every((e) => names.includes(e));
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontFamily: 'var(--mono)', fontSize: 12.5, marginBottom: 6, wordBreak: 'break-all' }}>
        Object.getOwnPropertyNames(window.{bridge.name} || {'{}'})
      </div>
      {err ? (
        <div className="note">error: {err}</div>
      ) : names.length === 0 ? (
        <div className="note">→ [] (object not injected on this origin)</div>
      ) : (
        <div>
          {names.map((n) => (
            <span className="chip" key={n}>
              {n}
            </span>
          ))}
        </div>
      )}
      {expect.length > 0 ? (
        <div className="expect">
          expected: [{expect.map((e) => `"${e}"`).join(', ')}]{' '}
          {names.length > 0 ? (
            <span className={matches ? 'status-bad' : ''}>{matches ? '— present' : '— differs'}</span>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
