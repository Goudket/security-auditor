import "dotenv/config";
import puppeteer from "puppeteer";
import { GoogleGenerativeAI } from "@google/generative-ai";
import { writeFileSync } from "fs";

// ── CLI & env validation ────────────────────────────────────────────────────

const targetUrl = process.argv[2];
if (!targetUrl) {
  console.error("Usage: node index.js <target-url>");
  process.exit(1);
}

const { GOOGLE_API_KEY } = process.env;
if (!GOOGLE_API_KEY) {
  console.error("Missing GOOGLE_API_KEY in .env");
  process.exit(1);
}

const parsedTarget = new URL(targetUrl);
const targetHostname = parsedTarget.hostname;
const targetOrigin = parsedTarget.origin;

// ── Wordlists & patterns ────────────────────────────────────────────────────

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
  "/accounts/", "/login/", "/register/", "/signup/",
];

const XSS_PROBES = [
  '<script>alert(1)</script>',
  '"><img src=x onerror=alert(1)>',
  "'-alert(1)-'",
];

const SQLI_PROBES = [
  "' OR '1'='1",
  "1; DROP TABLE users--",
  "' UNION SELECT NULL--",
];

const SQLI_ERROR_RE = [
  /sql syntax/i, /mysql_/i, /pg_query/i, /sqlite/i,
  /ORA-\d+/i, /Microsoft SQL/i, /unclosed quotation/i,
  /syntax error at or near/i, /unterminated string/i,
];

const STATIC_RE = /\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map)$/i;

// ── Helpers ─────────────────────────────────────────────────────────────────

function safeFetch(url, opts = {}) {
  return fetch(url, {
    redirect: "manual",
    headers: { "User-Agent": "SecurityAuditor/1.0" },
    signal: AbortSignal.timeout(8000),
    ...opts,
  });
}

// ── Phase 1 — Crawl & capture traffic via CDP ───────────────────────────────

async function crawlAndCapture(url) {
  console.log(`\n${"=".repeat(60)}`);
  console.log("[Phase 1] RECONNAISSANCE — Crawling & capturing traffic");
  console.log(`${"=".repeat(60)}`);
  console.log(`  Target: ${url}\n`);

  const browser = await puppeteer.launch({
    headless: true,
    args: ["--no-sandbox"],
  });

  const page = await browser.newPage();
  await page.setUserAgent(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAuditor/1.0"
  );

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
      postData: p.request.postData || null,
    });
  });

  cdp.on("Network.responseReceived", async (p) => {
    const req = reqMap.get(p.requestId);
    if (!req) return;
    const u = new URL(req.url);
    if (STATIC_RE.test(u.pathname)) return;

    let body = "";
    try {
      const r = await cdp.send("Network.getResponseBody", { requestId: p.requestId });
      body = r.body.slice(0, 2000);
    } catch { body = ""; }

    const h = p.response.headers;
    if (h["server"]) tech.server = h["server"];
    if (h["x-powered-by"]) tech.poweredBy = h["x-powered-by"];

    traffic.push({
      method: req.method,
      url: req.url,
      path: u.pathname,
      query: u.search || "",
      postData: req.postData,
      statusCode: p.response.status,
      responseHeaders: h,
      body,
    });
  });

  async function extractPageData() {
    const pageForms = await page.evaluate(() =>
      Array.from(document.querySelectorAll("form")).map((f) => ({
        action: f.action,
        method: f.method,
        inputs: Array.from(f.querySelectorAll("input,textarea,select")).map((i) => ({
          name: i.name, type: i.type, required: i.required,
        })),
      }))
    );
    forms.push(...pageForms);

    const pageSrc = await page.evaluate(() =>
      Array.from(document.querySelectorAll("script[src]")).map((s) => s.src)
    );
    pageSrc.forEach((s) => scripts.add(s));

    const pageTech = await page.evaluate(() => {
      const t = {};
      const gen = document.querySelector('meta[name="generator"]');
      if (gen) t.generator = gen.content;
      if (document.querySelector('input[name="csrfmiddlewaretoken"]')) t.framework = "Django";
      if (document.querySelector("[data-reactroot],[data-reactid]")) t.frontend = "React";
      if (document.querySelector("[ng-app],[data-ng-app]")) t.frontend = "Angular";
      if (document.querySelector("[data-v-]")) t.frontend = "Vue";
      return t;
    });
    Object.assign(tech, pageTech);
  }

  await page.goto(url, { waitUntil: "networkidle2", timeout: 30_000 });
  await extractPageData();

  const origin = new URL(url).origin;
  const links = await page.$$eval("a[href]", (anchors, orig) =>
    anchors.map((a) => a.href)
      .filter((h) => h.startsWith(orig))
      .filter((h, i, a) => a.indexOf(h) === i),
    origin
  );

  const toVisit = links.slice(0, 15);
  console.log(`  Found ${links.length} internal links, visiting up to ${toVisit.length}`);

  for (const link of toVisit) {
    try {
      console.log(`    → ${link}`);
      await page.goto(link, { waitUntil: "networkidle2", timeout: 20_000 });
      await extractPageData();
    } catch (err) {
      console.warn(`    ⚠ ${err.message}`);
    }
  }

  const cookies = await page.cookies();
  await browser.close();

  console.log(`\n  ✓ Captured ${traffic.length} requests`);
  console.log(`  ✓ Found ${forms.length} forms, ${scripts.size} scripts`);
  console.log(`  ✓ Technologies: ${JSON.stringify(tech)}`);
  console.log(`  ✓ Cookies: ${cookies.length}`);

  return { traffic, forms, cookies, tech, scripts: [...scripts] };
}

// ── Phase 2 — Passive security analysis ─────────────────────────────────────

function auditHeaders(traffic) {
  const findings = [];
  const seen = new Set();

  for (const e of traffic) {
    if (seen.has(e.path)) continue;
    seen.add(e.path);
    const h = e.responseHeaders;

    const missing = [];
    if (!h["strict-transport-security"]) missing.push("HSTS");
    if (!h["content-security-policy"]) missing.push("CSP");
    if (!h["x-content-type-options"]) missing.push("X-Content-Type-Options");
    if (!h["x-frame-options"] && !h["content-security-policy"]?.includes("frame-ancestors"))
      missing.push("X-Frame-Options");
    if (!h["referrer-policy"]) missing.push("Referrer-Policy");
    if (!h["permissions-policy"]) missing.push("Permissions-Policy");

    if (missing.length)
      findings.push({ type: "missing_headers", path: e.path, missing });

    if (h["server"])
      findings.push({ type: "server_disclosure", path: e.path, value: h["server"] });
    if (h["x-powered-by"])
      findings.push({ type: "tech_disclosure", path: e.path, value: h["x-powered-by"] });
    if (h["access-control-allow-origin"] === "*")
      findings.push({ type: "cors_wildcard", path: e.path });
  }

  return findings;
}

function auditCookies(cookies) {
  return cookies.map((c) => {
    const issues = [];
    if (!c.secure) issues.push("Missing Secure flag");
    if (!c.httpOnly) issues.push("Missing HttpOnly flag");
    if (!c.sameSite || c.sameSite === "None") issues.push(`SameSite=${c.sameSite || "unset"}`);
    return issues.length ? { name: c.name, domain: c.domain, issues } : null;
  }).filter(Boolean);
}

// ── Phase 3 — Active probing ────────────────────────────────────────────────

async function probeDirectories() {
  console.log("\n  [3a] Directory & sensitive path enumeration...");
  const findings = [];

  const results = await Promise.allSettled(
    SENSITIVE_PATHS.map(async (path) => {
      try {
        const res = await safeFetch(`${targetOrigin}${path}`);
        return { path, status: res.status };
      } catch { return null; }
    })
  );

  for (const r of results) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const { path, status } = r.value;
    if (status === 200) {
      findings.push({ path, status, severity: "medium", note: "Accessible" });
      console.log(`    ✓ ${path} → 200 (accessible!)`);
    } else if (status === 403) {
      findings.push({ path, status, severity: "info", note: "Forbidden but exists" });
      console.log(`    ✗ ${path} → 403 (exists, forbidden)`);
    } else if (status === 301 || status === 302) {
      findings.push({ path, status, severity: "info", note: "Redirects" });
    }
  }

  console.log(`    Probed ${SENSITIVE_PATHS.length} paths → ${findings.length} interesting`);
  return findings;
}

async function testCORS() {
  console.log("  [3b] CORS misconfiguration testing...");
  const findings = [];
  const origins = [
    "https://evil.com",
    "https://attacker.example.com",
    `https://${targetHostname}.evil.com`,
    "null",
  ];

  for (const origin of origins) {
    try {
      const res = await safeFetch(targetUrl, {
        headers: { Origin: origin, "User-Agent": "SecurityAuditor/1.0" },
      });
      const acao = res.headers.get("access-control-allow-origin");
      const acac = res.headers.get("access-control-allow-credentials");
      if (acao && (acao === "*" || acao === origin)) {
        findings.push({ origin, reflected: acao, credentials: acac === "true" });
        console.log(`    ⚠ Origin "${origin}" reflected! credentials=${acac}`);
      }
    } catch {}
  }

  return findings;
}

async function testXSS(traffic) {
  console.log("  [3c] Reflected XSS testing...");
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
          if (body.includes(payload)) {
            findings.push({ path: u.pathname, param: key, payload });
            console.log(`    ⚠ Reflected XSS: param "${key}" on ${u.pathname}`);
            break;
          }
        } catch {}
      }
    }
  }

  return findings;
}

async function testSQLi(traffic) {
  console.log("  [3d] SQL injection testing...");
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
            findings.push({ path: u.pathname, param: key, pattern: match.toString() });
            console.log(`    ⚠ SQL error: param "${key}" on ${u.pathname}`);
            break;
          }
        } catch {}
      }
    }
  }

  return findings;
}

async function testHTTPMethods(traffic) {
  console.log("  [3e] HTTP method testing...");
  const findings = [];
  const paths = [...new Set(traffic.map((t) => new URL(t.url).pathname))].slice(0, 5);

  for (const path of paths) {
    try {
      const res = await safeFetch(`${targetOrigin}${path}`, { method: "OPTIONS" });
      const allow = res.headers.get("allow");
      if (allow) {
        findings.push({ path, allowed: allow });
        console.log(`    ${path} allows: ${allow}`);
      }
    } catch {}

    try {
      const res = await safeFetch(`${targetOrigin}${path}`, { method: "TRACE" });
      if (res.status === 200) {
        findings.push({ path, trace: true });
        console.log(`    ⚠ TRACE enabled on ${path}`);
      }
    } catch {}
  }

  return findings;
}

// ── Phase 4 — Format & send to Gemini ───────────────────────────────────────

function formatFindings(data) {
  const sections = [];

  sections.push("## CAPTURED HTTP TRAFFIC\n");
  sections.push(data.traffic.map((e, i) => {
    const lines = [`#${i + 1}`, `${e.method} ${e.url}`, `Status: ${e.statusCode}`];
    if (e.postData) lines.push(`PostData: ${e.postData.slice(0, 500)}`);
    const sec = ["set-cookie", "x-frame-options", "content-security-policy",
      "strict-transport-security", "x-content-type-options",
      "access-control-allow-origin", "server", "x-powered-by"];
    const notable = Object.entries(e.responseHeaders)
      .filter(([k]) => sec.includes(k.toLowerCase()))
      .map(([k, v]) => `  ${k}: ${v}`);
    if (notable.length) lines.push(`Headers:\n${notable.join("\n")}`);
    if (e.body) lines.push(`Body: ${e.body.slice(0, 1000)}`);
    return lines.join("\n");
  }).join("\n---\n"));

  sections.push("\n## TECHNOLOGIES DETECTED\n" + JSON.stringify(data.tech, null, 2));

  if (data.forms.length) {
    sections.push("\n## FORMS DISCOVERED\n" + data.forms.map((f, i) =>
      `Form #${i + 1}: action=${f.action} method=${f.method}\n` +
      f.inputs.map((inp) => `  - ${inp.name || "(unnamed)"} [${inp.type}] required=${inp.required}`).join("\n")
    ).join("\n\n"));
  }

  if (data.cookies.length) {
    sections.push("\n## COOKIES\n" + data.cookies.map((c) =>
      `${c.name}: secure=${c.secure} httpOnly=${c.httpOnly} sameSite=${c.sameSite || "unset"} path=${c.path}`
    ).join("\n"));
  }

  if (data.headerFindings.length) {
    sections.push("\n## SECURITY HEADER ISSUES\n" + data.headerFindings.map((f) => {
      if (f.type === "missing_headers") return `${f.path}: Missing → ${f.missing.join(", ")}`;
      if (f.type === "server_disclosure") return `${f.path}: Server=${f.value}`;
      if (f.type === "tech_disclosure") return `${f.path}: X-Powered-By=${f.value}`;
      if (f.type === "cors_wildcard") return `${f.path}: CORS wildcard (*)`;
      return JSON.stringify(f);
    }).join("\n"));
  }

  if (data.cookieFindings.length) {
    sections.push("\n## COOKIE ISSUES\n" + data.cookieFindings.map((f) =>
      `${f.name} (${f.domain}): ${f.issues.join(", ")}`
    ).join("\n"));
  }

  if (data.dirFindings.length) {
    sections.push("\n## DIRECTORY ENUMERATION\n" + data.dirFindings.map((f) =>
      `${f.path} → ${f.status} (${f.note})`
    ).join("\n"));
  }

  if (data.corsFindings.length) {
    sections.push("\n## CORS MISCONFIGURATIONS\n" + data.corsFindings.map((f) =>
      `Origin "${f.origin}" → reflected as "${f.reflected}", credentials=${f.credentials}`
    ).join("\n"));
  }

  if (data.xssFindings.length) {
    sections.push("\n## REFLECTED XSS\n" + data.xssFindings.map((f) =>
      `${f.path} param="${f.param}" payload="${f.payload}"`
    ).join("\n"));
  }

  if (data.sqliFindings.length) {
    sections.push("\n## SQL INJECTION INDICATORS\n" + data.sqliFindings.map((f) =>
      `${f.path} param="${f.param}" error pattern=${f.pattern}`
    ).join("\n"));
  }

  if (data.methodFindings.length) {
    sections.push("\n## HTTP METHODS\n" + data.methodFindings.map((f) => {
      if (f.trace) return `${f.path}: TRACE enabled`;
      return `${f.path}: ${f.allowed}`;
    }).join("\n"));
  }

  return sections.join("\n");
}

async function analyzeWithGemini(blob) {
  console.log(`\n${"=".repeat(60)}`);
  console.log("[Phase 4] AI ANALYSIS — Sending findings to Gemini");
  console.log(`${"=".repeat(60)}\n`);

  const genAI = new GoogleGenerativeAI(GOOGLE_API_KEY);

  const systemPrompt = `You are a Senior Offensive Security Consultant writing a formal red team assessment report.
You will receive comprehensive security assessment data collected from automated reconnaissance and active probing of a web application.

The data includes: captured HTTP traffic, discovered forms, cookies, security header analysis, directory enumeration results, CORS tests, reflected XSS tests, SQL injection tests, and HTTP method tests.

Your job:
1. Analyze ALL provided data thoroughly — do not skip any section.
2. Identify and classify every vulnerability found.
3. For each vulnerability, explain the real-world attack scenario and business impact.
4. Provide proof-of-concept steps where possible.
5. Cross-reference findings (e.g., missing CSRF + exposed form = chained attack).

Output a professional Markdown report with these sections:

# Security Assessment Report

## Executive Summary
(3-5 sentences covering scope, methodology, overall risk posture, and critical findings count)

## Methodology
(Brief description of the phases: reconnaissance, passive analysis, active probing, AI analysis)

## Risk Summary
(Table: Severity | Count)

## Findings
(Table: ID | Severity | Title | Endpoint | CVSS estimate)

## Detailed Findings
(For EACH finding, include:)
### [ID] Title (Severity)
- **Endpoint:** ...
- **Evidence:** exact data from the assessment
- **Attack Scenario:** step-by-step exploitation
- **Business Impact:** what could go wrong
- **Remediation:** specific fix

## Attack Chains
(Describe how individual findings can be combined for greater impact)

## Recommendations
(Prioritized action items: Immediate / Short-term / Long-term)

## Appendix
(Raw statistics: total requests captured, paths probed, tests performed)

Use severity levels: Critical, High, Medium, Low, Informational.
Be thorough, specific, and cite exact evidence from the data.`;

  const model = genAI.getGenerativeModel({
    model: "gemini-3-flash-preview",
    systemInstruction: systemPrompt,
  });

  const result = await model.generateContent(
    `Complete security assessment data for **${targetHostname}** (${targetOrigin}):\n\n${blob}`
  );

  return result.response.text();
}

// ── Phase 5 — Save report ───────────────────────────────────────────────────

function saveReport(markdown) {
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = `report_${targetHostname}_${ts}.md`;
  writeFileSync(filename, markdown, "utf-8");
  console.log(`\n[Phase 5] Report saved → ${filename}`);
  return filename;
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const t0 = Date.now();

  try {
    // Phase 1 — Crawl & capture
    const { traffic, forms, cookies, tech, scripts } = await crawlAndCapture(targetUrl);

    if (traffic.length === 0) {
      console.warn("No relevant traffic captured — nothing to analyze.");
      process.exit(0);
    }

    // Phase 2 — Passive analysis
    console.log(`\n${"=".repeat(60)}`);
    console.log("[Phase 2] PASSIVE ANALYSIS — Headers, cookies, tech stack");
    console.log(`${"=".repeat(60)}`);

    const headerFindings = auditHeaders(traffic);
    console.log(`  ✓ ${headerFindings.length} header issues`);

    const cookieFindings = auditCookies(cookies);
    console.log(`  ✓ ${cookieFindings.length} cookie issues`);

    // Phase 3 — Active probing
    console.log(`\n${"=".repeat(60)}`);
    console.log("[Phase 3] ACTIVE PROBING — Testing for vulnerabilities");
    console.log(`${"=".repeat(60)}`);

    const dirFindings = await probeDirectories();
    const corsFindings = await testCORS();
    const xssFindings = await testXSS(traffic);
    const sqliFindings = await testSQLi(traffic);
    const methodFindings = await testHTTPMethods(traffic);

    const totalFindings = headerFindings.length + cookieFindings.length +
      dirFindings.length + corsFindings.length + xssFindings.length +
      sqliFindings.length + methodFindings.length;

    console.log(`\n  ── Total pre-AI findings: ${totalFindings}`);

    // Phase 4 — Gemini analysis
    const blob = formatFindings({
      traffic, forms, cookies, tech, scripts,
      headerFindings, cookieFindings, dirFindings,
      corsFindings, xssFindings, sqliFindings, methodFindings,
    });

    const report = await analyzeWithGemini(blob);

    // Phase 5 — Save
    const filename = saveReport(report);

    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    console.log(`\n${"=".repeat(60)}`);
    console.log(`  COMPLETE — ${elapsed}s elapsed`);
    console.log(`  Report: ${filename}`);
    console.log(`${"=".repeat(60)}\n`);
  } catch (err) {
    console.error("Fatal error:", err);
    process.exit(1);
  }
}

main();
