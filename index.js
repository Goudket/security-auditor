import "dotenv/config";
import puppeteer from "puppeteer";
import { writeFileSync } from "fs";
import { createInterface } from "readline/promises";
import { stdin as input, stdout as output } from "process";

let targetUrl = (process.argv[2] || "").trim();
let targetHostname = "";
let targetOrigin = "";
let targetProtocol = "";

const { OPENAI_API_KEY } = process.env;
if (!OPENAI_API_KEY) {
  console.error("Missing OPENAI_API_KEY in .env");
  process.exit(1);
}
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5.4-mini";

async function promptForTargetUrl() {
  const rl = createInterface({ input, output });
  try {
    const answer = await rl.question("Enter target URL (include http:// or https://): ");
    return answer.trim();
  } finally {
    rl.close();
  }
}

async function initializeTarget() {
  if (!targetUrl) {
    targetUrl = await promptForTargetUrl();
  }

  if (!targetUrl) {
    throw new Error("No URL provided.");
  }

  const parsed = new URL(targetUrl);
  if (!/^https?:$/.test(parsed.protocol)) {
    throw new Error("URL must start with http:// or https://");
  }

  targetHostname = parsed.hostname;
  targetOrigin = parsed.origin;
  targetProtocol = parsed.protocol;
}

const SENSITIVE_PATHS = [
  "/.env", "/.git/config", "/.git/HEAD",
  "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
  "/admin/", "/admin/login/", "/administrator/",
  "/api/", "/api/v1/", "/api/v2/", "/api/docs/", "/api/schema/",
  "/graphql", "/swagger/", "/swagger-ui/", "/openapi.json",
  "/debug/", "/server-info/", "/server-status/",
  "/wp-admin/", "/wp-login.php", "/phpinfo.php",
  "/health", "/healthz", "/status", "/metrics", "/prometheus/",
  "/flower/", "/celery/", "/monitoring/",
  "/console/", "/shell/", "/terminal/",
  "/config/", "/settings/", "/setup/",
  "/backup/", "/dump/", "/.DS_Store",
  "/accounts/", "/login/", "/register/", "/signup/"
];

const XSS_PROBES = [
  "<script>alert(1)</script>",
  '\"><img src=x onerror=alert(1)>',
  "'-alert(1)-'"
];

const SQLI_PROBES = [
  "' OR '1'='1",
  "' UNION SELECT NULL--",
  "\" OR \"1\"=\"1"
];

const SQLI_ERROR_RE = [
  /sql syntax/i, /mysql_/i, /pg_query/i, /sqlite/i,
  /ORA-\d+/i, /Microsoft SQL/i, /unclosed quotation/i,
  /syntax error at or near/i, /unterminated string/i,
  /PDOException/i, /SequelizeDatabaseError/i
];

const REDIRECT_PARAMS = [
  "next", "url", "redirect", "redirect_url", "return", "return_to",
  "returnUrl", "continue", "dest", "destination", "callback", "to", "go"
];

const STATIC_RE = /\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map)$/i;
const DIRECTORY_LISTING_RE = [
  /Index of\s*\//i,
  /Parent Directory/i,
  /Directory listing for/i
];

const SEVERITY_WEIGHT = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Informational: 1
};

function safeFetch(url, opts = {}) {
  return fetch(url, {
    redirect: "manual",
    headers: { "User-Agent": "SecurityAuditor/2.0" },
    signal: AbortSignal.timeout(10_000),
    ...opts
  });
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function countBySeverity(findings) {
  const counts = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Informational: 0
  };

  for (const finding of findings) {
    if (counts[finding.severity] !== undefined) counts[finding.severity] += 1;
  }

  return counts;
}

function summarizeStats(data, normalizedFindings, consolidatedFindings) {
  const uniqueAffectedEndpoints = new Set(
    consolidatedFindings.flatMap((f) => f.endpoints)
  );

  return {
    trafficCount: data.traffic.length,
    uniquePaths: new Set(data.traffic.map((e) => e.path)).size,
    formsCount: data.forms.length,
    scriptsCount: data.scripts.length,
    cookiesCount: data.cookies.length,
    sensitivePathsProbed: SENSITIVE_PATHS.length,
    totalRawFindings: normalizedFindings.length,
    totalConsolidatedFindings: consolidatedFindings.length,
    affectedEndpoints: uniqueAffectedEndpoints.size,
    bySeverity: countBySeverity(consolidatedFindings)
  };
}

function prioritizeActions(findings) {
  const sorted = [...findings].sort((a, b) => {
    const w = (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0);
    if (w !== 0) return w;
    return a.title.localeCompare(b.title);
  });

  const seen = new Set();
  const actions = [];
  for (const finding of sorted) {
    const key = `${finding.title}|${finding.remediation}`;
    if (seen.has(key)) continue;
    seen.add(key);
    actions.push({
      severity: finding.severity,
      action: finding.remediation,
      exampleEndpoint: finding.endpoints[0] || "(no endpoint)",
      reason: finding.evidenceSamples[0] || finding.title
    });
    if (actions.length >= 12) break;
  }

  return actions;
}

async function crawlAndCapture(url) {
  console.log(`\n${"=".repeat(60)}`);
  console.log("[Phase 1] Reconnaissance - crawl and capture traffic");
  console.log(`${"=".repeat(60)}`);
  console.log(`  Target: ${url}\n`);

  const browser = await puppeteer.launch({
    headless: true,
    args: ["--no-sandbox"]
  });

  const page = await browser.newPage();
  await page.setUserAgent("Mozilla/5.0 SecurityAuditor/2.0");

  const cdp = await page.createCDPSession();
  await cdp.send("Network.enable");

  const reqMap = new Map();
  const traffic = [];
  const forms = [];
  const scripts = new Set();
  const tech = {};

  cdp.on("Network.requestWillBeSent", (p) => {
    reqMap.set(p.requestId, {
      method: p.request.method,
      url: p.request.url,
      headers: p.request.headers,
      postData: p.request.postData || null
    });
  });

  cdp.on("Network.responseReceived", async (p) => {
    const req = reqMap.get(p.requestId);
    if (!req) return;

    let u;
    try {
      u = new URL(req.url);
    } catch {
      return;
    }

    if (STATIC_RE.test(u.pathname)) return;

    let body = "";
    try {
      const r = await cdp.send("Network.getResponseBody", { requestId: p.requestId });
      body = r.body.slice(0, 3000);
    } catch {
      body = "";
    }

    const h = p.response.headers || {};
    if (h.server) tech.server = h.server;
    if (h["x-powered-by"]) tech.poweredBy = h["x-powered-by"];

    traffic.push({
      method: req.method,
      url: req.url,
      path: u.pathname,
      query: u.search || "",
      postData: req.postData,
      statusCode: p.response.status,
      responseHeaders: h,
      body
    });
  });

  async function extractPageData() {
    const pageData = await page.evaluate(() => {
      const current = location.href;
      const forms = Array.from(document.querySelectorAll("form")).map((f) => ({
        pageUrl: current,
        action: f.action || current,
        method: (f.method || "GET").toUpperCase(),
        inputs: Array.from(f.querySelectorAll("input,textarea,select")).map((i) => ({
          name: i.name,
          type: i.type,
          required: i.required
        }))
      }));

      const scripts = Array.from(document.querySelectorAll("script[src]")).map((s) => s.src);

      const t = {};
      const generator = document.querySelector('meta[name="generator"]');
      if (generator) t.generator = generator.content;
      if (document.querySelector('input[name="csrfmiddlewaretoken"]')) t.framework = "Django";
      if (document.querySelector("[data-reactroot],[data-reactid]")) t.frontend = "React";
      if (document.querySelector("[ng-app],[data-ng-app]")) t.frontend = "Angular";
      if (document.querySelector("[data-v-]")) t.frontend = "Vue";

      return { forms, scripts, tech: t };
    });

    forms.push(...pageData.forms);
    pageData.scripts.forEach((s) => scripts.add(s));
    Object.assign(tech, pageData.tech);
  }

  await page.goto(url, { waitUntil: "networkidle2", timeout: 30_000 });
  await extractPageData();

  const origin = new URL(url).origin;
  const links = await page.$$eval(
    "a[href]",
    (anchors, orig) =>
      anchors
        .map((a) => a.href)
        .filter((h) => h.startsWith(orig))
        .filter((h, i, arr) => arr.indexOf(h) === i),
    origin
  );

  const toVisit = links.slice(0, 20);
  console.log(`  Found ${links.length} internal links, visiting up to ${toVisit.length}`);

  for (const link of toVisit) {
    try {
      console.log(`    -> ${link}`);
      await page.goto(link, { waitUntil: "networkidle2", timeout: 20_000 });
      await extractPageData();
    } catch (err) {
      console.warn(`    ! ${err.message}`);
    }
  }

  const cookies = await page.cookies();
  await browser.close();

  console.log(`\n  Captured ${traffic.length} requests`);
  console.log(`  Found ${forms.length} forms and ${scripts.size} scripts`);
  console.log(`  Technologies: ${JSON.stringify(tech)}`);
  console.log(`  Cookies: ${cookies.length}`);

  return { traffic, forms, cookies, tech, scripts: [...scripts] };
}

function auditHeaders(traffic) {
  const findings = [];
  const seen = new Set();

  for (const e of traffic) {
    if (seen.has(e.path)) continue;
    seen.add(e.path);

    const h = e.responseHeaders || {};
    const csp = (h["content-security-policy"] || "").toString();
    const missing = [];

    if (!h["strict-transport-security"]) missing.push("Strict-Transport-Security");
    if (!h["content-security-policy"]) missing.push("Content-Security-Policy");
    if (!h["x-content-type-options"]) missing.push("X-Content-Type-Options");
    if (!h["x-frame-options"] && !csp.includes("frame-ancestors")) missing.push("X-Frame-Options/frame-ancestors");
    if (!h["referrer-policy"]) missing.push("Referrer-Policy");
    if (!h["permissions-policy"]) missing.push("Permissions-Policy");

    if (missing.length) findings.push({ type: "missing_headers", path: e.path, missing });

    if (h.server) findings.push({ type: "server_disclosure", path: e.path, value: h.server });
    if (h["x-powered-by"]) findings.push({ type: "tech_disclosure", path: e.path, value: h["x-powered-by"] });
    if (h["access-control-allow-origin"] === "*") findings.push({ type: "cors_wildcard", path: e.path });

    const cacheControl = (h["cache-control"] || "").toString();
    if (/login|account|profile|dashboard|admin/i.test(e.path) && !/no-store|private/i.test(cacheControl)) {
      findings.push({ type: "weak_cache_control", path: e.path, value: cacheControl || "missing" });
    }
  }

  return findings;
}

function auditCookies(cookies) {
  return cookies
    .map((c) => {
      const issues = [];
      if (!c.secure) issues.push("Missing Secure flag");
      if (!c.httpOnly) issues.push("Missing HttpOnly flag");
      if (!c.sameSite || c.sameSite === "None") issues.push(`SameSite=${c.sameSite || "unset"}`);
      if (c.name.startsWith("__Host-") && (c.domain || c.path !== "/" || !c.secure)) {
        issues.push("Invalid __Host- cookie requirements (Secure, Path=/, no Domain)");
      }
      if (c.name.startsWith("__Secure-") && !c.secure) {
        issues.push("Invalid __Secure- cookie requirements (Secure=true)");
      }
      return issues.length ? { name: c.name, domain: c.domain, path: c.path, issues } : null;
    })
    .filter(Boolean);
}
function auditForms(forms) {
  const findings = [];

  for (const form of forms) {
    const lowerNames = form.inputs.map((i) => (i.name || "").toLowerCase());
    const hasCsrfToken = lowerNames.some((n) => /csrf|xsrf|authenticity|token/.test(n));
    const hasPassword = form.inputs.some((i) => (i.type || "").toLowerCase() === "password");

    if (form.method === "POST" && !hasCsrfToken) {
      findings.push({
        type: "missing_csrf",
        pageUrl: form.pageUrl,
        action: form.action,
        method: form.method
      });
    }

    if (hasPassword && form.action.startsWith("http://")) {
      findings.push({
        type: "insecure_password_transport",
        pageUrl: form.pageUrl,
        action: form.action
      });
    }

    const hasSensitiveFields = lowerNames.some((n) => /email|phone|address|card|ssn|token/.test(n));
    if (hasSensitiveFields && form.method === "GET") {
      findings.push({
        type: "sensitive_data_in_get",
        pageUrl: form.pageUrl,
        action: form.action
      });
    }
  }

  return findings;
}

function auditScripts(scripts) {
  const findings = [];
  if (!targetUrl.startsWith("https://")) return findings;

  for (const src of scripts) {
    if (src.startsWith("http://")) {
      findings.push({ type: "mixed_content_script", src });
    }
  }

  return findings;
}

function auditTransport() {
  const findings = [];
  if (targetProtocol === "http:") {
    findings.push({
      type: "insecure_transport",
      endpoint: targetOrigin,
      note: "Target URL is HTTP, not HTTPS"
    });
  }
  return findings;
}

async function probeDirectories() {
  console.log("\n  [3a] Directory and sensitive path enumeration...");
  const findings = [];

  const results = await Promise.allSettled(
    SENSITIVE_PATHS.map(async (path) => {
      try {
        const res = await safeFetch(`${targetOrigin}${path}`);
        const text = await res.text();
        return {
          path,
          status: res.status,
          bodySample: text.slice(0, 400)
        };
      } catch {
        return null;
      }
    })
  );

  for (const r of results) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const { path, status, bodySample } = r.value;

    if (status === 200) {
      const hasDirectoryListing = DIRECTORY_LISTING_RE.some((re) => re.test(bodySample));
      findings.push({
        path,
        status,
        severity: hasDirectoryListing ? "high" : "medium",
        note: hasDirectoryListing ? "Directory listing exposed" : "Accessible"
      });
      console.log(`    + ${path} -> ${status}`);
    } else if (status === 401 || status === 403) {
      findings.push({
        path,
        status,
        severity: "info",
        note: "Exists but access-controlled"
      });
    } else if ([301, 302, 307, 308].includes(status)) {
      findings.push({ path, status, severity: "info", note: "Redirects" });
    }
  }

  console.log(`    Probed ${SENSITIVE_PATHS.length} paths -> ${findings.length} interesting`);
  return findings;
}

async function inspectDiscoveryFiles() {
  console.log("  [3b] Discovery file intelligence (robots/security.txt)...");
  const findings = [];

  try {
    const robotsRes = await safeFetch(`${targetOrigin}/robots.txt`);
    if (robotsRes.status === 200) {
      const text = await robotsRes.text();
      const sensitiveDisallow = text
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => /^disallow:/i.test(line))
        .map((line) => line.split(":").slice(1).join(":").trim())
        .filter((p) => /admin|internal|private|backup|staging|debug/i.test(p));

      if (sensitiveDisallow.length) {
        findings.push({
          type: "robots_sensitive_paths",
          endpoint: "/robots.txt",
          paths: sensitiveDisallow.slice(0, 10)
        });
      }
    }
  } catch {}

  try {
    const secRes = await safeFetch(`${targetOrigin}/.well-known/security.txt`);
    if (secRes.status !== 200) {
      findings.push({
        type: "missing_security_txt",
        endpoint: "/.well-known/security.txt"
      });
    }
  } catch {
    findings.push({
      type: "missing_security_txt",
      endpoint: "/.well-known/security.txt"
    });
  }

  return findings;
}

async function testCORS() {
  console.log("  [3c] CORS misconfiguration testing...");
  const findings = [];
  const origins = [
    "https://evil.com",
    "https://attacker.example.com",
    `https://${targetHostname}.evil.com`,
    "null"
  ];

  for (const origin of origins) {
    try {
      const res = await safeFetch(targetUrl, {
        headers: {
          Origin: origin,
          "User-Agent": "SecurityAuditor/2.0"
        }
      });

      const acao = res.headers.get("access-control-allow-origin");
      const acac = res.headers.get("access-control-allow-credentials");
      const reflected = acao && (acao === "*" || acao === origin);

      if (reflected) {
        findings.push({
          origin,
          reflected: acao,
          credentials: acac === "true",
          severity: acac === "true" ? "high" : "medium"
        });
        console.log(`    ! Origin ${origin} reflected with credentials=${acac}`);
      }
    } catch {}
  }

  return findings;
}

function isLikelyReflectedXSS(body, payload) {
  if (!body) return false;
  if (body.includes(payload)) return true;

  const encoded = payload
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

  return body.includes(encoded);
}

async function testXSS(traffic) {
  console.log("  [3d] Reflected XSS testing...");
  const findings = [];
  const tested = new Set();

  for (const entry of traffic) {
    if (entry.method !== "GET") continue;

    const u = new URL(entry.url);
    if (!u.search || tested.has(u.pathname)) continue;
    tested.add(u.pathname);

    for (const [key] of u.searchParams) {
      for (const payload of XSS_PROBES) {
        try {
          const test = new URL(entry.url);
          test.searchParams.set(key, payload);

          const res = await safeFetch(test.toString());
          const body = await res.text();

          if (isLikelyReflectedXSS(body, payload)) {
            findings.push({
              path: u.pathname,
              param: key,
              payload,
              status: res.status
            });
            console.log(`    ! Reflection found on ${u.pathname} param=${key}`);
            break;
          }
        } catch {}
      }
    }
  }

  return findings;
}

async function testSQLi(traffic) {
  console.log("  [3e] SQL injection error-based testing...");
  const findings = [];
  const tested = new Set();

  for (const entry of traffic) {
    if (entry.method !== "GET") continue;

    const u = new URL(entry.url);
    if (!u.search || tested.has(u.pathname)) continue;
    tested.add(u.pathname);

    for (const [key] of u.searchParams) {
      for (const payload of SQLI_PROBES) {
        try {
          const test = new URL(entry.url);
          test.searchParams.set(key, payload);
          const res = await safeFetch(test.toString());
          const body = await res.text();
          const match = SQLI_ERROR_RE.find((re) => re.test(body));

          if (match) {
            findings.push({
              path: u.pathname,
              param: key,
              payload,
              matchedPattern: match.toString()
            });
            console.log(`    ! SQL error pattern found on ${u.pathname} param=${key}`);
            break;
          }
        } catch {}
      }
    }
  }

  return findings;
}

async function testOpenRedirect(traffic) {
  console.log("  [3f] Open redirect testing...");
  const findings = [];
  const testedUrls = new Set();

  for (const entry of traffic) {
    if (entry.method !== "GET") continue;

    const u = new URL(entry.url);
    if (!u.search) continue;

    const signature = `${u.pathname}?${[...u.searchParams.keys()].sort().join("&")}`;
    if (testedUrls.has(signature)) continue;
    testedUrls.add(signature);

    for (const [key] of u.searchParams) {
      if (!REDIRECT_PARAMS.includes(key)) continue;

      try {
        const attack = new URL(entry.url);
        const attackerTarget = "https://example.com/redirect-canary";
        attack.searchParams.set(key, attackerTarget);

        const res = await safeFetch(attack.toString());
        const location = res.headers.get("location") || "";
        const isExternalRedirect = /^https?:\/\//i.test(location) && !location.startsWith(targetOrigin);

        if ([301, 302, 303, 307, 308].includes(res.status) && isExternalRedirect) {
          findings.push({
            path: u.pathname,
            param: key,
            status: res.status,
            location
          });
          console.log(`    ! Open redirect candidate at ${u.pathname} param=${key}`);
        }
      } catch {}
    }
  }

  return findings;
}

async function testHTTPMethods(traffic) {
  console.log("  [3g] HTTP method testing...");
  const findings = [];
  const paths = [...new Set(traffic.map((t) => new URL(t.url).pathname))].slice(0, 8);

  for (const path of paths) {
    try {
      const optionsRes = await safeFetch(`${targetOrigin}${path}`, { method: "OPTIONS" });
      const allow = optionsRes.headers.get("allow") || "";

      if (allow) {
        const risky = ["TRACE", "TRACK", "CONNECT", "PUT", "DELETE", "PATCH"].filter((m) =>
          new RegExp(`\\b${escapeRegex(m)}\\b`, "i").test(allow)
        );

        findings.push({
          path,
          allowed: allow,
          riskyMethods: risky
        });
      }
    } catch {}

    try {
      const traceRes = await safeFetch(`${targetOrigin}${path}`, { method: "TRACE" });
      if (traceRes.status === 200) {
        findings.push({ path, traceEnabled: true });
        console.log(`    ! TRACE enabled on ${path}`);
      }
    } catch {}
  }

  return findings;
}
function normalizeFindings(data) {
  const normalized = [];
  let idx = 1;

  const push = (severity, title, endpoint, evidence, remediation) => {
    normalized.push({
      id: `F-${String(idx).padStart(3, "0")}`,
      severity,
      title,
      endpoint,
      evidence,
      remediation
    });
    idx += 1;
  };

  for (const f of data.transportFindings) {
    push(
      "High",
      "Application served over HTTP",
      f.endpoint,
      f.note,
      "Enforce HTTPS with 301 redirects and enable HSTS with preload-ready settings."
    );
  }

  for (const f of data.headerFindings) {
    if (f.type === "missing_headers") {
      push(
        "Medium",
        "Missing security headers",
        f.path,
        `Missing: ${f.missing.join(", ")}`,
        "Add the missing headers at the reverse proxy/app layer and verify with integration tests."
      );
    } else if (f.type === "server_disclosure") {
      push(
        "Low",
        "Server banner disclosure",
        f.path,
        `Server header: ${f.value}`,
        "Remove or normalize server banners in HTTP responses."
      );
    } else if (f.type === "tech_disclosure") {
      push(
        "Low",
        "Technology stack disclosure",
        f.path,
        `X-Powered-By: ${f.value}`,
        "Disable framework disclosure headers in production."
      );
    } else if (f.type === "cors_wildcard") {
      push(
        "Medium",
        "CORS wildcard enabled",
        f.path,
        "Access-Control-Allow-Origin is wildcard (*)",
        "Restrict Access-Control-Allow-Origin to trusted origins and deny credentials for wildcard cases."
      );
    } else if (f.type === "weak_cache_control") {
      push(
        "Medium",
        "Sensitive endpoint cache policy is weak",
        f.path,
        `Cache-Control: ${f.value}`,
        "Set Cache-Control: no-store on authenticated and sensitive pages."
      );
    }
  }

  for (const f of data.cookieFindings) {
    push(
      "Medium",
      "Cookie security flags are weak",
      `${f.domain}${f.path || "/"}`,
      `${f.name}: ${f.issues.join("; ")}`,
      "Set Secure, HttpOnly, and SameSite=Lax/Strict on session cookies and enforce cookie prefix requirements."
    );
  }

  for (const f of data.formFindings) {
    if (f.type === "missing_csrf") {
      push(
        "High",
        "Potential missing CSRF protection on POST form",
        f.action,
        `Form at ${f.pageUrl} uses POST without visible CSRF token input`,
        "Require anti-CSRF tokens on state-changing actions and validate token server-side."
      );
    } else if (f.type === "insecure_password_transport") {
      push(
        "High",
        "Password form submits over HTTP",
        f.action,
        `Password field observed at ${f.pageUrl}`,
        "Serve login/register exclusively on HTTPS and reject plaintext HTTP submissions."
      );
    } else if (f.type === "sensitive_data_in_get") {
      push(
        "Medium",
        "Sensitive fields submitted via GET",
        f.action,
        `Sensitive form fields detected at ${f.pageUrl} using GET`,
        "Use POST for sensitive input and avoid exposing PII in URLs/logs/referrers."
      );
    }
  }

  for (const f of data.scriptFindings) {
    push(
      "High",
      "Mixed content script load",
      f.src,
      "HTTPS page loads JavaScript over HTTP",
      "Load all active content over HTTPS only and enable CSP upgrade-insecure-requests where appropriate."
    );
  }

  for (const f of data.dirFindings) {
    if (f.status === 200) {
      push(
        f.note === "Directory listing exposed" ? "High" : "Medium",
        "Sensitive path is reachable",
        f.path,
        `${f.path} returned HTTP ${f.status} (${f.note})`,
        "Block direct access to sensitive routes/files and enforce authz checks server-side."
      );
    }
  }

  for (const f of data.discoveryFindings) {
    if (f.type === "robots_sensitive_paths") {
      push(
        "Informational",
        "robots.txt discloses sensitive path hints",
        f.endpoint,
        `Disallow entries: ${f.paths.join(", ")}`,
        "Ensure listed paths are genuinely protected and avoid exposing unnecessary internal route names."
      );
    } else if (f.type === "missing_security_txt") {
      push(
        "Low",
        "security.txt missing",
        f.endpoint,
        "No RFC 9116 security.txt discovered",
        "Publish /.well-known/security.txt to improve coordinated vulnerability disclosure."
      );
    }
  }

  for (const f of data.corsFindings) {
    push(
      f.credentials ? "High" : "Medium",
      "CORS origin reflection",
      targetOrigin,
      `Origin=${f.origin} reflected as ${f.reflected}, credentials=${f.credentials}`,
      "Implement explicit origin allowlists and avoid credentialed cross-origin access for untrusted origins."
    );
  }

  for (const f of data.xssFindings) {
    push(
      "High",
      "Reflected input detected (XSS candidate)",
      f.path,
      `Parameter ${f.param} reflected payload (status ${f.status})`,
      "Apply context-aware output encoding, strict input validation, and CSP with no unsafe-inline."
    );
  }

  for (const f of data.sqliFindings) {
    push(
      "High",
      "SQL error leakage on user-controlled parameter",
      f.path,
      `Param=${f.param}, pattern=${f.matchedPattern}`,
      "Use parameterized queries everywhere and replace detailed DB errors with generic responses."
    );
  }

  for (const f of data.openRedirectFindings) {
    push(
      "Medium",
      "Open redirect candidate",
      f.path,
      `Param=${f.param}, location=${f.location}, status=${f.status}`,
      "Allow redirects only to vetted internal paths or signed allowlisted destinations."
    );
  }

  for (const f of data.methodFindings) {
    if (f.traceEnabled) {
      push(
        "Medium",
        "TRACE method enabled",
        f.path,
        "TRACE returned HTTP 200",
        "Disable TRACE/TRACK at the web server and upstream proxy."
      );
      continue;
    }

    if (f.riskyMethods && f.riskyMethods.length > 0) {
      push(
        "Medium",
        "Potentially risky HTTP methods allowed",
        f.path,
        `Allow header contains: ${f.riskyMethods.join(", ")}`,
        "Restrict unsupported methods and enforce per-route method allowlists."
      );
    }
  }

  normalized.sort((a, b) => {
    const diff = (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0);
    if (diff !== 0) return diff;
    return a.title.localeCompare(b.title);
  });

  return normalized;
}

function consolidateFindings(normalizedFindings) {
  const grouped = new Map();

  for (const finding of normalizedFindings) {
    const key = `${finding.severity}|${finding.title}|${finding.remediation}`;
    if (!grouped.has(key)) {
      grouped.set(key, {
        severity: finding.severity,
        title: finding.title,
        remediation: finding.remediation,
        endpoints: new Set(),
        evidenceSamples: []
      });
    }

    const entry = grouped.get(key);
    if (finding.endpoint) entry.endpoints.add(finding.endpoint);
    if (finding.evidence && !entry.evidenceSamples.includes(finding.evidence) && entry.evidenceSamples.length < 5) {
      entry.evidenceSamples.push(finding.evidence);
    }
  }

  const consolidated = [...grouped.values()]
    .map((entry) => ({
      severity: entry.severity,
      title: entry.title,
      remediation: entry.remediation,
      endpoints: [...entry.endpoints].sort(),
      evidenceSamples: entry.evidenceSamples
    }))
    .sort((a, b) => {
      const diff = (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0);
      if (diff !== 0) return diff;
      return a.title.localeCompare(b.title);
    })
    .map((entry, idx) => ({
      id: `G-${String(idx + 1).padStart(3, "0")}`,
      ...entry
    }));

  return consolidated;
}

function renderLocalReport(consolidatedFindings, topActions, stats) {
  const lines = [];

  lines.push("# Security Assessment Report");
  lines.push("");
  lines.push("## Executive Summary");
  lines.push(
    `Automated reconnaissance and active probing were performed against ${targetOrigin}. ` +
      `The scan captured ${stats.trafficCount} HTTP interactions across ${stats.uniquePaths} unique paths. ` +
      `Raw findings: ${stats.totalRawFindings}; consolidated findings: ${stats.totalConsolidatedFindings}. ` +
      `Highest risks are concentrated in findings classified as ${stats.bySeverity.Critical + stats.bySeverity.High} High/Critical. ` +
      "Prioritized remediation actions are listed below."
  );
  lines.push("");

  lines.push("## Risk Summary");
  lines.push("| Severity | Count |");
  lines.push("|---|---:|");
  lines.push(`| Critical | ${stats.bySeverity.Critical} |`);
  lines.push(`| High | ${stats.bySeverity.High} |`);
  lines.push(`| Medium | ${stats.bySeverity.Medium} |`);
  lines.push(`| Low | ${stats.bySeverity.Low} |`);
  lines.push(`| Informational | ${stats.bySeverity.Informational} |`);
  lines.push(`| Total (Consolidated) | ${stats.totalConsolidatedFindings} |`);
  lines.push("");

  lines.push("## Top Remediation Actions");
  if (topActions.length === 0) {
    lines.push("No actionable security findings were produced by the current checks.");
  } else {
    for (const [i, action] of topActions.entries()) {
      lines.push(`${i + 1}. [${action.severity}] ${action.action}`);
      lines.push(`   Example endpoint: ${action.exampleEndpoint}`);
      lines.push(`   Why now: ${action.reason}`);
    }
  }
  lines.push("");

  lines.push("## Detailed Findings");
  if (consolidatedFindings.length === 0) {
    lines.push("No security findings detected by automated checks.");
  } else {
    for (const f of consolidatedFindings) {
      const shownEndpoints = f.endpoints.slice(0, 15).join(", ");
      const extraCount = Math.max(0, f.endpoints.length - 15);
      const endpointSummary =
        f.endpoints.length === 0
          ? "(none)"
          : extraCount > 0
            ? `${shownEndpoints} (+${extraCount} more)`
            : shownEndpoints;

      lines.push(`### ${f.id} - ${f.title} (${f.severity})`);
      lines.push(`- Affected endpoints (${f.endpoints.length}): ${endpointSummary}`);
      lines.push(`- Evidence samples: ${f.evidenceSamples.join(" | ") || "(none)"}`);
      lines.push(`- Remediation: ${f.remediation}`);
      lines.push("");
    }
  }

  lines.push("## Appendix");
  lines.push(`- Target: ${targetOrigin}`);
  lines.push(`- Total HTTP requests captured: ${stats.trafficCount}`);
  lines.push(`- Unique paths observed: ${stats.uniquePaths}`);
  lines.push(`- Forms discovered: ${stats.formsCount}`);
  lines.push(`- Scripts discovered: ${stats.scriptsCount}`);
  lines.push(`- Cookies observed: ${stats.cookiesCount}`);
  lines.push(`- Sensitive paths probed: ${stats.sensitivePathsProbed}`);
  lines.push(`- Consolidated affected endpoints: ${stats.affectedEndpoints}`);

  return lines.join("\n");
}

function formatFindingsForAI(data, consolidatedFindings, topActions, stats) {
  const sections = [];

  sections.push("## SCAN STATISTICS");
  sections.push(JSON.stringify(stats, null, 2));

  sections.push("\n## CONSOLIDATED FINDINGS");
  sections.push(
    consolidatedFindings
      .map(
        (f) =>
          `${f.id} | ${f.severity} | ${f.title} | affected_endpoints=${f.endpoints.length}\nEndpoints: ${f.endpoints.join(", ")}\nEvidence samples: ${f.evidenceSamples.join(" | ")}\nRemediation: ${f.remediation}`
      )
      .join("\n---\n")
  );

  sections.push("\n## TOP ACTIONS");
  sections.push(
    topActions
      .map(
        (a, i) =>
          `${i + 1}. [${a.severity}] ${a.action}\nExample endpoint: ${a.exampleEndpoint}\nReason: ${a.reason}`
      )
      .join("\n")
  );

  sections.push("\n## RAW TECH STACK");
  sections.push(JSON.stringify(data.tech, null, 2));

  sections.push("\n## RAW FORM SNAPSHOT");
  sections.push(JSON.stringify(data.forms.slice(0, 20), null, 2));

  sections.push("\n## RAW COOKIE SNAPSHOT");
  sections.push(JSON.stringify(data.cookies.slice(0, 30), null, 2));

  return sections.join("\n");
}

async function analyzeWithOpenAI(blob) {
  console.log(`\n${"=".repeat(60)}`);
  console.log(`[Phase 4] AI analysis - send findings to OpenAI (${OPENAI_MODEL})`);
  console.log(`${"=".repeat(60)}\n`);

  const systemPrompt = `You are a senior application security consultant writing an actionable engineering report.
Use only the provided evidence.

Output Markdown with these sections:
1) Executive Summary
2) Risk Summary (table: Severity | Count)
3) Immediate Actions (top 10, each with owner suggestion: App/Platform/SRE)
4) Findings (table: ID | Severity | Title | Affected Endpoints | Business Impact)
5) Detailed Findings
For each finding include:
- Evidence (exact)
- Exploitation path (realistic)
- Fix plan (concrete code/config-level actions)
- Validation steps (how to verify fix in CI or tests)
6) Attack Chains
7) 30/60/90 day remediation roadmap

Consolidate duplicate findings under one title. Do not create repeated entries for the same issue class.
For each consolidated finding, list all affected endpoints together.

If confidence is low for any finding, explicitly flag it as "Needs Manual Validation".`;

  const userPrompt = `Complete security assessment dataset for ${targetHostname} (${targetOrigin}):\n\n${blob}`;

  const res = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${OPENAI_API_KEY}`
    },
    body: JSON.stringify({
      model: OPENAI_MODEL,
      input: [
        {
          role: "system",
          content: [
            { type: "input_text", text: systemPrompt }
          ]
        },
        {
          role: "user",
          content: [
            { type: "input_text", text: userPrompt }
          ]
        }
      ]
    }),
    signal: AbortSignal.timeout(120_000)
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`OpenAI API error (${res.status}): ${errText.slice(0, 500)}`);
  }

  const data = await res.json();
  if (typeof data.output_text === "string" && data.output_text.trim()) {
    return data.output_text;
  }

  // Fallback for alternate response shapes.
  const combined = (data.output || [])
    .flatMap((item) => item.content || [])
    .map((part) => part.text)
    .filter(Boolean)
    .join("\n");

  if (!combined.trim()) {
    throw new Error("OpenAI response did not include text output.");
  }

  return combined;
}

function saveArtifacts(markdown, normalizedFindings, consolidatedFindings, stats) {
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const reportFile = `report_${targetHostname}_${ts}.md`;
  const jsonFile = `findings_${targetHostname}_${ts}.json`;

  writeFileSync(reportFile, markdown, "utf-8");
  writeFileSync(
    jsonFile,
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        target: targetOrigin,
        stats,
        findings: normalizedFindings,
        consolidatedFindings
      },
      null,
      2
    ),
    "utf-8"
  );

  console.log(`\n[Phase 5] Report saved -> ${reportFile}`);
  console.log(`[Phase 5] Machine-readable findings saved -> ${jsonFile}`);

  return { reportFile, jsonFile };
}

async function main() {
  const t0 = Date.now();

  try {
    await initializeTarget();
    const { traffic, forms, cookies, tech, scripts } = await crawlAndCapture(targetUrl);

    if (traffic.length === 0) {
      console.warn("No relevant traffic captured. Nothing to analyze.");
      process.exit(0);
    }

    console.log(`\n${"=".repeat(60)}`);
    console.log("[Phase 2] Passive checks");
    console.log(`${"=".repeat(60)}`);

    const headerFindings = auditHeaders(traffic);
    const cookieFindings = auditCookies(cookies);
    const formFindings = auditForms(forms);
    const scriptFindings = auditScripts(scripts);
    const transportFindings = auditTransport();

    console.log(`  Header findings: ${headerFindings.length}`);
    console.log(`  Cookie findings: ${cookieFindings.length}`);
    console.log(`  Form findings: ${formFindings.length}`);
    console.log(`  Script findings: ${scriptFindings.length}`);
    console.log(`  Transport findings: ${transportFindings.length}`);

    console.log(`\n${"=".repeat(60)}`);
    console.log("[Phase 3] Active probing");
    console.log(`${"=".repeat(60)}`);

    const dirFindings = await probeDirectories();
    const discoveryFindings = await inspectDiscoveryFiles();
    const corsFindings = await testCORS();
    const xssFindings = await testXSS(traffic);
    const sqliFindings = await testSQLi(traffic);
    const openRedirectFindings = await testOpenRedirect(traffic);
    const methodFindings = await testHTTPMethods(traffic);

    const allRaw = {
      traffic,
      forms,
      cookies,
      tech,
      scripts,
      headerFindings,
      cookieFindings,
      formFindings,
      scriptFindings,
      transportFindings,
      dirFindings,
      discoveryFindings,
      corsFindings,
      xssFindings,
      sqliFindings,
      openRedirectFindings,
      methodFindings
    };

    const normalizedFindings = normalizeFindings(allRaw);
    const consolidatedFindings = consolidateFindings(normalizedFindings);
    const stats = summarizeStats(allRaw, normalizedFindings, consolidatedFindings);
    const topActions = prioritizeActions(consolidatedFindings);

    console.log(`\n  Total raw findings: ${normalizedFindings.length}`);
    console.log(`  Total consolidated findings: ${consolidatedFindings.length}`);

    const localReport = renderLocalReport(consolidatedFindings, topActions, stats);

    let finalReport = localReport;
    try {
      const blobForAI = formatFindingsForAI(allRaw, consolidatedFindings, topActions, stats);
      finalReport = await analyzeWithOpenAI(blobForAI);
    } catch (aiErr) {
      console.warn(`AI analysis failed, using deterministic report only: ${aiErr.message}`);
    }

    const { reportFile, jsonFile } = saveArtifacts(
      finalReport,
      normalizedFindings,
      consolidatedFindings,
      stats
    );

    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    console.log(`\n${"=".repeat(60)}`);
    console.log(`COMPLETE - ${elapsed}s elapsed`);
    console.log(`Report: ${reportFile}`);
    console.log(`Findings JSON: ${jsonFile}`);
    console.log(`${"=".repeat(60)}\n`);
  } catch (err) {
    console.error("Fatal error:", err);
    process.exit(1);
  }
}

main();
