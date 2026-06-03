import express, { Request, Response } from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI, Type } from '@google/genai';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(express.json({ limit: '20mb' }));

const PORT = 3000;

// Initialize Google GenAI
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    },
  },
});

// Hardcoded credential regexes for high-reliability static analysis
const REGEX_PATTERNS = [
  {
    name: 'Google API Key',
    regex: /AIzaSy[A-Za-z0-9_-]{35}/g,
    category: 'Google Cloud / Maps Platform',
    severity: 'high' as const,
    desc: 'Potential exposed Google API token or Maps credential found.',
    resol: 'Rotate the API key immediately. Apply HTTP referrer restrictions or wrap within a server-side proxy router.'
  },
  {
    name: 'AWS Access Key ID',
    regex: /\b(AKIA|ASCA)[0-9A-Z]{16}\b/g,
    category: 'AWS Infrastructure',
    severity: 'high' as const,
    desc: 'Exposed AWS IAM Access Key static identifier.',
    resol: 'Deactivate these credentials in AWS IAM immediately. Migrate to AWS Secrets Manager or secure IAM Instance Roles.'
  },
  {
    name: 'Stripe Secret Key',
    regex: /\bsk_(test|live)_[0-9a-zA-Z]{24,99}\b/g,
    category: 'Stripe Payments',
    severity: 'high' as const,
    desc: 'Exposed Stripe API private secret key.',
    resol: 'Revoke and rotate the Stripe key in your administration panel immediately. Secret keys must live entirely server-side.'
  },
  {
    name: 'Stripe Publishable Key',
    regex: /\bpk_(test|live)_[0-9a-zA-Z]{24,99}\b/g,
    category: 'Stripe Payments',
    severity: 'low' as const,
    desc: 'Public-facing Stripe publishable integration key.',
    resol: 'Public keys are generally safe but ensure domain-verification limits are configured in your Stripe Dashboard.'
  },
  {
    name: 'Slack Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]{8,11}\/B[0-9A-Z]{8,11}\/[A-Za-z0-9]{24}/g,
    category: 'Slack Webhooks',
    severity: 'high' as const,
    desc: 'Exposed critical Slack notification webhook endpoint.',
    resol: 'Revoke the webhook connection on Slack integrations panel and convert to custom secure server-side variables.'
  },
  {
    name: 'Basic / Bearer Auth Tokens',
    regex: /\b(Authorization|Bearer)\s*:\s*(?:["']?)[Bb]earer\s+[A-Za-z0-9\-._~+/]{24,}(?:["']?)/g,
    category: 'HTTP Authentication Keys',
    severity: 'medium' as const,
    desc: 'Exposed static Authorization token or service credentials header.',
    resol: 'Refrain from committing hardcoded tokens. Read credentials dynamically from modern Environment Parameter managers.'
  },
  {
    name: 'Database URL / Credentials Connection String',
    regex: /\b(?:mongodb(?:\+srv)?|postgres|postgresql|mysql|mssql):\/\/[A-Za-z0-9_.~-]+:[A-Za-z0-9_.~-]+@[A-Za-z0-9_.-]+(?::\d+)?\/[A-Za-z0-9_.-]+/g,
    category: 'Database Connection',
    severity: 'high' as const,
    desc: 'Plaintext database connection credential uri.',
    resol: 'Redact these credentials. Place database details under environment secrets on your application container manager.'
  },
  {
    name: 'Private Authentication Key Boundary',
    regex: /-----BEGIN (RSA|EC|DSA|OPENSSH)? PRIVATE KEY-----[\s\S]*?-----END (RSA|EC|DSA|OPENSSH)? PRIVATE KEY-----/g,
    category: 'Private Keys',
    severity: 'high' as const,
    desc: 'PlainText Certificate Private Key declaration.',
    resol: 'Remove the private key block immediately. Generate new system keypairs.'
  },
];

// Extracted endpoint discovery patterns
const ENDPOINT_URL_REGEX = /https?:\/\/[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=]+/g;

// Helper function to local regex scan
function scanLocalRegex(content: string, filename: string) {
  const findings: any[] = [];
  const lines = content.split('\n');

  for (const pattern of REGEX_PATTERNS) {
    pattern.regex.lastIndex = 0; // reset
    let match;
    while ((match = pattern.regex.exec(content)) !== null) {
      const matchText = match[0];
      const matchIndex = match.index;
      
      // Calculate line number
      let lineNumber = 1;
      let count = 0;
      for (let i = 0; i < matchIndex; i++) {
        if (content[i] === '\n') {
          lineNumber++;
        }
      }

      // Context line
      const contextLine = lines[lineNumber - 1] || '';
      
      // Partially mask secret for safe showing
      const length = matchText.length;
      let masked = matchText;
      if (length > 10) {
        masked = matchText.substring(0, 5) + '...' + matchText.substring(length - 5);
      }

      findings.push({
        id: `regex-${pattern.name.replace(/\s+/g, '-').toLowerCase()}-${lineNumber}-${Math.random().toString(36).substr(2, 5)}`,
        type: 'secret',
        severity: pattern.severity,
        title: `Hardcoded ${pattern.name} Exposed`,
        description: pattern.desc,
        fileOrUrl: filename,
        lineNumber,
        evidence: contextLine.trim(),
        resolution: pattern.resol,
        category: pattern.category,
      });
    }
  }

  // Also query generic endpoints inside files
  const endpoints: any[] = [];
  ENDPOINT_URL_REGEX.lastIndex = 0;
  let urlMatch;
  while ((urlMatch = ENDPOINT_URL_REGEX.exec(content)) !== null) {
    const urlStr = urlMatch[0];
    
    // Ignore standard UI links, asset files, and common schemas
    if (
      urlStr.includes('w3.org') ||
      urlStr.includes('schema.org') ||
      urlStr.includes('github.com') ||
      urlStr.includes('npmjs.com') ||
      urlStr.match(/\.(png|jpg|jpeg|gif|svg|css|woff2|woff|ttf|ico|json|html)$/i)
    ) {
      continue;
    }

    let urlObj;
    try {
      urlObj = new URL(urlStr);
    } catch {
      continue;
    }

    const domain = urlObj.hostname;
    const pathVal = urlObj.pathname + urlObj.search;
    
    // Ignore local references or default schemas
    if (domain === 'localhost' || domain === '127.0.0.1') continue;

    // Calculate line number
    const matchIndex = urlMatch.index;
    let lineNumber = 1;
    for (let i = 0; i < matchIndex; i++) {
      if (content[i] === '\n') {
        lineNumber++;
      }
    }
    const contextLine = lines[lineNumber - 1] || '';

    // Determine category based on keywords
    let cat = 'External Integrations';
    if (domain.includes('google') || domain.includes('googleapis') || domain.includes('firebase')) {
      cat = 'Google Platform / Maps';
    } else if (domain.includes('stripe') || domain.includes('paypal') || domain.includes('braintree')) {
      cat = 'Payment Gateway';
    } else if (domain.includes('aws') || domain.includes('amazon') || domain.includes('s3')) {
      cat = 'Cloud Storage / IAM';
    } else if (domain.includes('facebook') || domain.includes('twitter') || domain.includes('github')) {
      cat = 'OAuth / Social API';
    }

    endpoints.push({
      id: `end-${Math.random().toString(36).substr(2, 9)}`,
      domain,
      path: pathVal,
      method: 'GET/POST',
      fileOrUrl: filename,
      lineNumber,
      category: cat,
      secured: urlObj.protocol === 'https:',
      usageExcerpt: contextLine.trim(),
    });
  }

  return { findings, endpoints };
}

// REST Route for scanning code
app.post('/api/scan/code', async (req: Request, res: Response) => {
  const { files } = req.body; // Array of { name: string, content: string }

  if (!files || !Array.isArray(files) || files.length === 0) {
    res.status(400).json({ error: 'No files provided for audit scanning.' });
    return;
  }

  try {
    const allFindings: any[] = [];
    const allEndpoints: any[] = [];
    
    // Process local regex scanner first
    for (const f of files) {
      const local = scanLocalRegex(f.content, f.name);
      allFindings.push(...local.findings);
      allEndpoints.push(...local.endpoints);
    }

    // Prepare content summary for Gemini analysis to find complex patterns,
    // analyze threats, design security ratings, and summarize risks
    const codeSummaries = files.map(f => {
      // Truncate file content to prevent token overflow if very long
      const maxChars = 20000;
      const content = f.content.length > maxChars 
        ? f.content.substring(0, maxChars) + '\n... [truncated]' 
        : f.content;
      return `File: ${f.name}\n\`\`\`\n${content}\n\`\`\``;
    }).join('\n\n');

    const prompt = `You are a certified Lead Security Auditor specializing in DevSecOps and static application security testing (SAST).
Analyze the following source files used in an in-house corporate application.
Determine if there are exposed APIs (external/internal), secret credentials, authorization keys, API connection details, and overall security compliance.

Here are the code files for review:
${codeSummaries}

Provide your evaluation and audits in strict JSON format. We are focused on identifying:
1. Additional API Endpoints or third-party query URLs, their domains, and path structures (representing them in the \`endpoints\` field).
2. Exposed credentials, database logins, secrets, or unmasked authorization headers that the static regex may have missed, or validate existing findings (representing them in the \`findings\` field).
3. Code vulnerabilities specifically regarding API usage (e.g., calling services over unsecure HTTP, missing input sanitizations on API responses, storing keys as plaintext, standard CORS misconfiguration).
4. A security scorecard grading (from A to F) and numeric rating (0 to 100), along with a summary of the compliance posture.

Format clean JSON output conforming exactly to this structure:
{
  "findings": [
    {
      "id": "gemini-find-1",
      "type": "secret" | "endpoint" | "libraries" | "compliance",
      "severity": "high" | "medium" | "low" | "info",
      "title": "Short descriptive name",
      "description": "Deep audit evaluation of what the issue is and why it's a risk",
      "fileOrUrl": "Filename",
      "lineNumber": 15,
      "evidence": "Exact code block showing the issue",
      "resolution": "Actionable, precise guide on how to fix and secure this API or key integration",
      "category": "API Platform Core category (e.g., Stripe Payments, AWS Cloud, Google Maps Platform)"
    }
  ],
  "endpoints": [
    {
      "id": "gemini-end-1",
      "domain": "api.service.com",
      "path": "/v1/resource",
      "method": "POST/GET",
      "fileOrUrl": "Filename",
      "lineNumber": 25,
      "category": "e.g., Payment Gateway, Analytics, Database Cloud",
      "secured": true,
      "usageExcerpt": "Code block utilizing this endpoint"
    }
  ],
  "scorecard": {
    "score": 85,
    "grade": "B",
    "totalFindings": 3,
    "highCount": 1,
    "mediumCount": 1,
    "lowCount": 1,
    "infoCount": 0,
    "assessmentSummary": "A concise executive evaluation on the security posture and contractor compliance."
  },
  "complianceChecks": [
    {
      "name": "Check Name",
      "passed": true,
      "description": "Short explanation",
      "remediation": "Optionally how to get it passed if failed"
    }
  ]
}`;

    // Query Gemini
    const result = await ai.models.generateContent({
      model: 'gemini-3.5-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          required: ['findings', 'endpoints', 'scorecard', 'complianceChecks'],
          properties: {
            findings: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                required: ['id', 'type', 'severity', 'title', 'description', 'fileOrUrl', 'evidence', 'resolution', 'category'],
                properties: {
                  id: { type: Type.STRING },
                  type: { type: Type.STRING },
                  severity: { type: Type.STRING },
                  title: { type: Type.STRING },
                  description: { type: Type.STRING },
                  fileOrUrl: { type: Type.STRING },
                  lineNumber: { type: Type.INTEGER },
                  evidence: { type: Type.STRING },
                  resolution: { type: Type.STRING },
                  category: { type: Type.STRING },
                },
              },
            },
            endpoints: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                required: ['id', 'domain', 'path', 'method', 'fileOrUrl', 'category', 'secured', 'usageExcerpt'],
                properties: {
                  id: { type: Type.STRING },
                  domain: { type: Type.STRING },
                  path: { type: Type.STRING },
                  method: { type: Type.STRING },
                  fileOrUrl: { type: Type.STRING },
                  lineNumber: { type: Type.INTEGER },
                  category: { type: Type.STRING },
                  secured: { type: Type.BOOLEAN },
                  usageExcerpt: { type: Type.STRING },
                },
              },
            },
            scorecard: {
              type: Type.OBJECT,
              required: ['score', 'grade', 'totalFindings', 'highCount', 'mediumCount', 'lowCount', 'infoCount', 'assessmentSummary'],
              properties: {
                score: { type: Type.INTEGER },
                grade: { type: Type.STRING },
                totalFindings: { type: Type.INTEGER },
                highCount: { type: Type.INTEGER },
                mediumCount: { type: Type.INTEGER },
                lowCount: { type: Type.INTEGER },
                infoCount: { type: Type.INTEGER },
                assessmentSummary: { type: Type.STRING },
              },
            },
            complianceChecks: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                required: ['name', 'passed', 'description'],
                properties: {
                  name: { type: Type.STRING },
                  passed: { type: Type.BOOLEAN },
                  description: { type: Type.STRING },
                  remediation: { type: Type.STRING },
                },
              },
            },
          },
        },
      },
    });

    const reportText = result.text;
    const aiReport = JSON.parse(reportText || '{}');

    // Combine Regex Static Scan with Gemini Smart Scan findings
    const mergedFindings = [...allFindings];
    const mergedEndpoints = [...allEndpoints];

    // Filter duplicates or augment findings safely
    if (aiReport.findings && Array.isArray(aiReport.findings)) {
      for (const find of aiReport.findings) {
        // Prevent simple duplicates by looking at evidence overlaps
        const exists = mergedFindings.some(f => 
          f.evidence.replace(/\s+/g, '') === find.evidence.replace(/\s+/g, '') ||
          (f.lineNumber === find.lineNumber && f.fileOrUrl === find.fileOrUrl && f.title === find.title)
        );
        if (!exists) {
          mergedFindings.push(find);
        }
      }
    }

    if (aiReport.endpoints && Array.isArray(aiReport.endpoints)) {
      for (const end of aiReport.endpoints) {
        const exists = mergedEndpoints.some(e => 
          e.domain === end.domain && 
          e.path.split('?')[0] === end.path.split('?')[0] &&
          e.fileOrUrl === end.fileOrUrl
        );
        if (!exists) {
          mergedEndpoints.push(end);
        }
      }
    }

    // Re-verify counts and override scorecard values for robustness
    const highVal = mergedFindings.filter(f => f.severity === 'high').length;
    const medVal = mergedFindings.filter(f => f.severity === 'medium').length;
    const lowVal = mergedFindings.filter(f => f.severity === 'low').length;
    const infoVal = mergedFindings.filter(f => f.severity === 'info').length;
    
    // Adjust security score based on severity counts: High: -20, Medium: -10, Low: -3
    let score = 100 - (highVal * 15) - (medVal * 8) - (lowVal * 3);
    if (score < 5) score = 5; // absolute minimum
    
    let grade = 'A';
    if (score < 60) grade = 'F';
    else if (score < 70) grade = 'D';
    else if (score < 80) grade = 'C';
    else if (score < 90) grade = 'B';

    const mergedScorecard = {
      score,
      grade,
      totalFindings: mergedFindings.length,
      highCount: highVal,
      mediumCount: medVal,
      lowCount: lowVal,
      infoCount: infoVal,
      assessmentSummary: aiReport.scorecard?.assessmentSummary || 'Audit finished with manual and cognitive checks.'
    };

    res.json({
      timestamp: new Date().toISOString(),
      targetName: files.length === 1 ? files[0].name : `${files.length} Source files`,
      targetType: 'code',
      findings: mergedFindings,
      endpoints: mergedEndpoints,
      scorecard: mergedScorecard,
      complianceChecks: aiReport.complianceChecks || [
        { name: 'Plaintext Credentials Check', passed: highVal === 0, description: 'Audits for hardcoded secrets, certificate private keys and database URIs.' },
        { name: 'Transport Security Verification', passed: mergedEndpoints.every(e => e.secured), description: 'Checks if all discovered third-party integrations communicate over secure TLS HTTPS endpoints.' },
        { name: 'Contractor Compliance Audit', passed: highVal === 0 && medVal === 0, description: 'Ensures external developers adhered to secure parameter-configuration guidelines.' }
      ]
    });

  } catch (err: any) {
    console.error('Audit Engine Failure:', err);
    res.status(500).json({ error: 'Failed when analyzing application assets: ' + err.message });
  }
});

// REST Route for scanning website URLs (Auditing exposed public assets)
app.post('/api/scan/url', async (req: Request, res: Response) => {
  const { url } = req.body;

  if (!url) {
    res.status(400).json({ error: 'URL is required to perform audit.' });
    return;
  }

  // Enforce secure protocol parsing as a defensive measure
  let cleanUrl = url.trim();
  if (!/^https?:\/\//i.test(cleanUrl)) {
    cleanUrl = 'https://' + cleanUrl;
  }

  try {
    const parsedTarget = new URL(cleanUrl);
    
    // Fetch website HTML source securely
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000); // 6 second max fetch timeout

    const fetchRes = await fetch(cleanUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) API Audit Agent / corporate compliance checks',
      },
      signal: controller.signal,
    });
    
    clearTimeout(timeoutId);

    if (!fetchRes.ok) {
      throw new Error(`Target landing returned response status ${fetchRes.status} ${fetchRes.statusText}`);
    }

    const htmlContent = await fetchRes.text();
    
    // Parse for script tags, style references, external networks, form targets
    const scriptSrcs: string[] = [];
    const scriptRegex = /<script\b[^>]*src=["']([^"']+)["']/gi;
    let match;
    while ((match = scriptRegex.exec(htmlContent)) !== null) {
      let src = match[1];
      if (src.startsWith('//')) {
        src = parsedTarget.protocol + src;
      } else if (src.startsWith('/')) {
        src = parsedTarget.origin + src;
      } else if (!/^https?:\/\//i.test(src)) {
        src = parsedTarget.origin + '/' + src;
      }
      scriptSrcs.push(src);
    }

    // Standard local scan on the main HTML document
    const local = scanLocalRegex(htmlContent, 'Main Page HTML (index)');
    const allFindings = [...local.findings];
    const allEndpoints = [...local.endpoints];

    // Scrape up to 2 public scripts from same hostname to audit client-side javascript key exposure (e.g. firebase keys, Gmaps)
    const remoteScriptsMatched = scriptSrcs.filter(src => {
      try {
        const u = new URL(src);
        return u.hostname === parsedTarget.hostname || u.pathname.includes('assets') || src.includes('main') || src.includes('index');
      } catch {
        return false;
      }
    }).slice(0, 3);

    for (const src of remoteScriptsMatched) {
      try {
        const jsController = new AbortController();
        const jsTimeout = setTimeout(() => jsController.abort(), 3000);
        const jsRes = await fetch(src, { signal: jsController.signal });
        clearTimeout(jsTimeout);
        
        if (jsRes.ok) {
          const jsCode = await jsRes.text();
          // Scan specific js files
          const filename = path.basename(new URL(src).pathname) || 'main.js';
          const jsLocal = scanLocalRegex(jsCode, `Public asset: ${filename}`);
          allFindings.push(...jsLocal.findings);
          allEndpoints.push(...jsLocal.endpoints);
        }
      } catch (scriptErr) {
        // Continue silently on single asset fetch failures
        console.warn(`Could not read remote asset ${src}:`, scriptErr);
      }
    }

    // Now call Gemini to perform Cognitive Audit of the HTML structure and public assets
    const truncatedHtml = htmlContent.length > 25000 ? htmlContent.substring(0, 25000) + '\n... [truncated]' : htmlContent;
    
    const prompt = `You are a certified cybercompliance static auditor. I am auditing one of my customer-facing websites that my local contractors deployed.
Analyze the following extracted HTML content and resources to check for embedded API keys, unmasked telemetry endpoint URLs, authentication exposures, in-page form action weaknesses, or non-HTTPS assets.

Target Host: ${parsedTarget.hostname}
Full Landing Page URL: ${cleanUrl}
Discovered Script links: ${scriptSrcs.slice(0, 5).join(', ')}

HTML Structure snippet:
\`\`\`html
${truncatedHtml}
\`\`\`

Provide your compliance evaluation and findings strictly in JSON format. We need to identify:
1. Public-facing Third-party APIs accessed in script declarations (Google Maps SDKs, Auth0, Stripe Client, Segment tracking, etc.).
2. High-Severity Exposure risks, such as active keys, DB connection variables visible in markup, or insecure API routes.
3. Transport compliance check.
4. Scorecard rating (0 to 100) and grade (A to F).

Use this identical JSON output schema:
{
  "findings": [
    {
      "id": "url-find-1",
      "type": "secret" | "endpoint" | "libraries" | "compliance",
      "severity": "high" | "medium" | "low" | "info",
      "title": "Short descriptive header",
      "description": "Risk audit evaluation and context",
      "fileOrUrl": "${parsedTarget.hostname} Landing Page",
      "evidence": "HTML line snippet or keyword context",
      "resolution": "Actionable path to fix this exposure",
      "category": "API Platform Category"
    }
  ],
  "endpoints": [
    {
      "id": "url-end-1",
      "domain": "api-host.com",
      "path": "/v1/api",
      "method": "CLIENT-LOAD",
      "fileOrUrl": "${parsedTarget.hostname} index source",
      "category": "e.g., Maps, Payment Processor, Telemetry",
      "secured": true,
      "usageExcerpt": "Code asset usage context"
    }
  ],
  "scorecard": {
    "score": 90,
    "grade": "A",
    "totalFindings": 1,
    "highCount": 0,
    "mediumCount": 1,
    "lowCount": 0,
    "infoCount": 0,
    "assessmentSummary": "A concise dashboard audit of the exposed web portal."
  },
  "complianceChecks": [
    {
      "name": "Check Name",
      "passed": true,
      "description": "Short explanation"
    }
  ]
}`;

    const result = await ai.models.generateContent({
      model: 'gemini-3.5-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          required: ['findings', 'endpoints', 'scorecard', 'complianceChecks'],
          properties: {
            findings: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                required: ['id', 'type', 'severity', 'title', 'description', 'fileOrUrl', 'evidence', 'resolution', 'category'],
                properties: {
                  id: { type: Type.STRING },
                  type: { type: Type.STRING },
                  severity: { type: Type.STRING },
                  title: { type: Type.STRING },
                  description: { type: Type.STRING },
                  fileOrUrl: { type: Type.STRING },
                  lineNumber: { type: Type.INTEGER },
                  evidence: { type: Type.STRING },
                  resolution: { type: Type.STRING },
                  category: { type: Type.STRING },
                },
              },
            },
            endpoints: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                required: ['id', 'domain', 'path', 'method', 'fileOrUrl', 'category', 'secured', 'usageExcerpt'],
                properties: {
                  id: { type: Type.STRING },
                  domain: { type: Type.STRING },
                  path: { type: Type.STRING },
                  method: { type: Type.STRING },
                  fileOrUrl: { type: Type.STRING },
                  lineNumber: { type: Type.INTEGER },
                  category: { type: Type.STRING },
                  secured: { type: Type.BOOLEAN },
                  usageExcerpt: { type: Type.STRING },
                },
              },
            },
            scorecard: {
              type: Type.OBJECT,
              required: ['score', 'grade', 'totalFindings', 'highCount', 'mediumCount', 'lowCount', 'infoCount', 'assessmentSummary'],
              properties: {
                score: { type: Type.INTEGER },
                grade: { type: Type.STRING },
                totalFindings: { type: Type.INTEGER },
                highCount: { type: Type.INTEGER },
                mediumCount: { type: Type.INTEGER },
                lowCount: { type: Type.INTEGER },
                infoCount: { type: Type.INTEGER },
                assessmentSummary: { type: Type.STRING },
              },
            },
            complianceChecks: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                required: ['name', 'passed', 'description'],
                properties: {
                  name: { type: Type.STRING },
                  passed: { type: Type.BOOLEAN },
                  description: { type: Type.STRING },
                  remediation: { type: Type.STRING },
                },
              },
            },
          },
        },
      },
    });

    const aiReport = JSON.parse(result.text || '{}');

    // Combine local scans with Gemini cognitive scan
    const mergedFindings = [...allFindings];
    const mergedEndpoints = [...allEndpoints];

    if (aiReport.findings && Array.isArray(aiReport.findings)) {
      for (const find of aiReport.findings) {
        const exists = mergedFindings.some(f => 
          f.evidence.replace(/\s+/g, '') === find.evidence.replace(/\s+/g, '') ||
          (f.title === find.title && f.category === find.category)
        );
        if (!exists) {
          mergedFindings.push(find);
        }
      }
    }

    if (aiReport.endpoints && Array.isArray(aiReport.endpoints)) {
      for (const end of aiReport.endpoints) {
        const exists = mergedEndpoints.some(e => 
          e.domain === end.domain && 
          e.path.split('?')[0] === end.path.split('?')[0]
        );
        if (!exists) {
          mergedEndpoints.push(end);
        }
      }
    }

    // Re-verify counts and override scorecard values for robustness
    const highVal = mergedFindings.filter(f => f.severity === 'high').length;
    const medVal = mergedFindings.filter(f => f.severity === 'medium').length;
    const lowVal = mergedFindings.filter(f => f.severity === 'low').length;
    const infoVal = mergedFindings.filter(f => f.severity === 'info').length;
    
    // Adjust security score based on severity counts: High: -15, Medium: -8, Low: -2
    let score = 100 - (highVal * 15) - (medVal * 8) - (lowVal * 2);
    if (score < 5) score = 5; // absolute minimum
    
    let grade = 'A';
    if (score < 60) grade = 'F';
    else if (score < 70) grade = 'D';
    else if (score < 80) grade = 'C';
    else if (score < 90) grade = 'B';

    const mergedScorecard = {
      score,
      grade,
      totalFindings: mergedFindings.length,
      highCount: highVal,
      mediumCount: medVal,
      lowCount: lowVal,
      infoCount: infoVal,
      assessmentSummary: aiReport.scorecard?.assessmentSummary || 'Audited exposed public-facing document elements successfully.'
    };

    res.json({
      timestamp: new Date().toISOString(),
      targetName: parsedTarget.hostname,
      targetType: 'url',
      findings: mergedFindings,
      endpoints: mergedEndpoints,
      scorecard: mergedScorecard,
      complianceChecks: aiReport.complianceChecks || [
        { name: 'TLS Encryption Connection', passed: cleanUrl.startsWith('https://'), description: 'Verify page assets load securely over HTTPS with SSL/TLS certificate.' },
        { name: 'Exposed Credentials Audit', passed: highVal === 0, description: 'Audits the index document assets for static programmatic secret leaking.' },
        { name: 'Public Script Security Check', passed: scriptSrcs.length > 0 && scriptSrcs.every(s => s.startsWith('https://')), description: 'Ensures external modular files load over secure connections.' }
      ]
    });

  } catch (err: any) {
    console.error('URL Fetch Scanner Failure:', err);
    res.status(500).json({ error: 'Audit target loading failed. Ensure the URL is valid, public, and server endpoint active: ' + err.message });
  }
});

// REST Route for scanning multiple website URLs in a secure multi-target batch
app.post('/api/scan/batch-urls', async (req: Request, res: Response) => {
  const { urls } = req.body;

  if (!urls || !Array.isArray(urls) || urls.length === 0) {
    res.status(400).json({ error: 'An array of URLs is required to execute a batch security audit.' });
    return;
  }

  // Normalize URLs and filter duplicates, with a threshold limit of 5 targets for optimal response
  const uniqueUrls = Array.from(new Set(urls.map(u => typeof u === 'string' ? u.trim() : '').filter(Boolean))).slice(0, 5);

  if (uniqueUrls.length === 0) {
    res.status(400).json({ error: 'Please supply at least one valid target URL.' });
    return;
  }

  const scannedTargets: any[] = [];

  for (const url of uniqueUrls) {
    let cleanUrl = url;
    if (!/^https?:\/\//i.test(cleanUrl)) {
      cleanUrl = 'https://' + cleanUrl;
    }

    try {
      const parsedTarget = new URL(cleanUrl);
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000); // 4 seconds timeout per URL to be responsive

      const fetchRes = await fetch(cleanUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) API Audit Agent / corporate compliance checks',
        },
        signal: controller.signal,
      });
      
      clearTimeout(timeoutId);

      if (!fetchRes.ok) {
        throw new Error(`Endpoint returned status code ${fetchRes.status}`);
      }

      const htmlContent = await fetchRes.text();
      
      // Parse for scripts
      const scriptSrcs: string[] = [];
      const scriptRegex = /<script\b[^>]*src=["']([^"']+)["']/gi;
      let match;
      while ((match = scriptRegex.exec(htmlContent)) !== null) {
        let src = match[1];
        if (src.startsWith('//')) {
          src = parsedTarget.protocol + src;
        } else if (src.startsWith('/')) {
          src = parsedTarget.origin + src;
        } else if (!/^https?:\/\//i.test(src)) {
          src = parsedTarget.origin + '/' + src;
        }
        scriptSrcs.push(src);
      }

      // Local Regex Scan on main HTML
      const local = scanLocalRegex(htmlContent, parsedTarget.hostname);
      const targetFindings = [...local.findings];
      const targetEndpoints = [...local.endpoints];

      // Scan up to 2 referenced script files for leaked keys
      const remoteScripts = scriptSrcs.filter(src => {
        try {
          const u = new URL(src);
          return u.hostname === parsedTarget.hostname || src.includes('assets') || src.includes('main') || src.includes('index');
        } catch { return false; }
      }).slice(0, 2);

      for (const src of remoteScripts) {
         try {
           const jsUrl = new URL(src);
           const jsController = new AbortController();
           const jsTimeout = setTimeout(() => jsController.abort(), 2000); // 2 second timeout per asset
           const jsRes = await fetch(src, { signal: jsController.signal });
           clearTimeout(jsTimeout);
           if (jsRes.ok) {
             const jsCode = await jsRes.text();
             const jsFilename = path.basename(jsUrl.pathname) || 'script.js';
             const jsLocal = scanLocalRegex(jsCode, `${parsedTarget.hostname}/${jsFilename}`);
             targetFindings.push(...jsLocal.findings);
             targetEndpoints.push(...jsLocal.endpoints);
           }
         } catch {}
      }

      scannedTargets.push({
        url: cleanUrl,
        success: true,
        hostname: parsedTarget.hostname,
        htmlContent: htmlContent.substring(0, 15000), // pass a cropped version securely to Gemini
        scriptSrcs,
        findings: targetFindings,
        endpoints: targetEndpoints,
        score: 100 // default placeholder to compute
      });

    } catch (err: any) {
      scannedTargets.push({
        url: cleanUrl,
        success: false,
        hostname: cleanUrl.replace(/^https?:\/\//i, '').split('/')[0] || cleanUrl,
        error: err.message || 'Connection reset or network port unreachable.',
        findings: [],
        endpoints: []
      });
    }
  }

  // Compile batch dynamic AI prompt for Gemini
  try {
    const summaryList = scannedTargets.map(t => 
      `Target: ${t.hostname} (${t.url}) - Status: ${t.success ? 'PARSED' : `FAILED (${t.error})`}`
    ).join('\n');

    const prompt = `You are a certified cybercompliance static auditor. I am auditing a batch of website targets.
Create a unified cyber-compliance report and scorecard evaluating these targets.

Sites requested in this audit batch:
${summaryList}

Parsed site details:
${scannedTargets.filter(t => t.success).map(t => `
--- Website: ${t.hostname} ---
Local regex findings: ${JSON.stringify(t.findings)}
Local endpoints: ${JSON.stringify(t.endpoints)}
Top page HTML structure:
\`\`\`html
${t.htmlContent}
\`\`\`
`).join('\n\n')}

Formulate a comprehensive master response returning:
1. "findings": Combined list of findings across ALL parsed target hostnames. Let the 'fileOrUrl' field contain the exact target domain hostname (e.g. "${scannedTargets[0]?.hostname || 'target.com'}"). For any target site that failed to connect, include a medium severity finding of type 'compliance' explaining that the connection was dropped.
2. "endpoints": Consolidated list of client-side third-party query endpoints found on these target hostnames.
3. "scorecard": Consolidated multi-target assessment scorecard with a final combined security score (0 to 100), overall Grade (A to F), and a cohesive "assessmentSummary" detailing which sites had critical key exposures or handshake errors.
4. "complianceChecks": Pass/fail checks across the whole suite (SSL encryption standards, exposed credentials, script sanitisation).

Format strictly as JSON following this schema:
{
  "findings": [
    {
      "id": "batch-find-1",
      "type": "secret" | "endpoint" | "libraries" | "compliance",
      "severity": "high" | "medium" | "low" | "info",
      "title": "Short header",
      "description": "Compliance evaluation and context",
      "fileOrUrl": "Target Domain",
      "evidence": "Source code text snippet",
      "resolution": "Action list to remedy exposure",
      "category": "e.g. AWS Infrastructure, Google Maps, Stripe"
    }
  ],
  "endpoints": [
    {
      "id": "batch-end-1",
      "domain": "api.segment.io",
      "path": "/v1/t",
      "method": "POST",
      "fileOrUrl": "Target Domain",
      "category": "Analytics",
      "secured": true,
      "usageExcerpt": "Script payload reference"
    }
  ],
  "scorecard": {
    "score": 85,
    "grade": "B",
    "totalFindings": 2,
    "highCount": 0,
    "mediumCount": 1,
    "lowCount": 1,
    "infoCount": 0,
    "assessmentSummary": "Brief overview of all parsed hostnames in this audit round."
  },
  "complianceChecks": [
    {
      "name": "Check Title",
      "passed": true,
      "description": "Short explanation text"
    }
  ]
}

Ensure the output is 100% compliant with standard JSON format and fully matching active schema variables. No preamble or conversational markdown outside the clean JSON block.`;

    const result = await ai.models.generateContent({
      model: 'gemini-3.5-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          required: ['findings', 'endpoints', 'scorecard', 'complianceChecks'],
          properties: {
            findings: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                required: ['id', 'type', 'severity', 'title', 'description', 'fileOrUrl', 'evidence', 'resolution', 'category'],
                properties: {
                  id: { type: Type.STRING },
                  type: { type: Type.STRING },
                  severity: { type: Type.STRING },
                  title: { type: Type.STRING },
                  description: { type: Type.STRING },
                  fileOrUrl: { type: Type.STRING },
                  lineNumber: { type: Type.INTEGER },
                  evidence: { type: Type.STRING },
                  resolution: { type: Type.STRING },
                  category: { type: Type.STRING },
                },
              },
            },
            endpoints: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                required: ['id', 'domain', 'path', 'method', 'fileOrUrl', 'category', 'secured', 'usageExcerpt'],
                properties: {
                  id: { type: Type.STRING },
                  domain: { type: Type.STRING },
                  path: { type: Type.STRING },
                  method: { type: Type.STRING },
                  fileOrUrl: { type: Type.STRING },
                  lineNumber: { type: Type.INTEGER },
                  category: { type: Type.STRING },
                  secured: { type: Type.BOOLEAN },
                  usageExcerpt: { type: Type.STRING },
                },
              },
            },
            scorecard: {
              type: Type.OBJECT,
              required: ['score', 'grade', 'totalFindings', 'highCount', 'mediumCount', 'lowCount', 'infoCount', 'assessmentSummary'],
              properties: {
                score: { type: Type.INTEGER },
                grade: { type: Type.STRING },
                totalFindings: { type: Type.INTEGER },
                highCount: { type: Type.INTEGER },
                mediumCount: { type: Type.INTEGER },
                lowCount: { type: Type.INTEGER },
                infoCount: { type: Type.INTEGER },
                assessmentSummary: { type: Type.STRING },
              },
            },
            complianceChecks: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                required: ['name', 'passed', 'description'],
                properties: {
                  name: { type: Type.STRING },
                  passed: { type: Type.BOOLEAN },
                  description: { type: Type.STRING },
                  remediation: { type: Type.STRING },
                },
              },
            },
          },
        },
      },
    });

    const aiReport = JSON.parse(result.text || '{}');

    // Aggregate scanned results
    const combinedFindings: any[] = [];
    const combinedEndpoints: any[] = [];

    // Prioritize regex scans from individual successful parses for precise compliance evidence
    for (const target of scannedTargets) {
      if (target.success) {
        combinedFindings.push(...target.findings);
        combinedEndpoints.push(...target.endpoints);
      } else {
        // Create formal network threat exception finding for failed sites
        combinedFindings.push({
          id: `net-fail-${target.hostname}-${Math.random().toString(36).substr(2, 5)}`,
          type: 'compliance',
          severity: 'medium',
          title: `Audit connection failed for target ${target.hostname}`,
          description: `The compliance sniffer could not reach the endpoint landing page. Reason: ${target.error}`,
          fileOrUrl: target.hostname,
          evidence: `TCP connection dropped: ${target.url}`,
          resolution: `Verify DNS records, firewall rules, and certificate validation for requested hostname. Secure edge networks against unexpected outages.`,
          category: 'Boundary Compliance Risk'
        });
      }
    }

    // Merge in any other findings identified by Gemini
    if (aiReport.findings && Array.isArray(aiReport.findings)) {
      for (const find of aiReport.findings) {
        const dup = combinedFindings.some(f => 
          f.evidence.replace(/\s+/g, '') === find.evidence.replace(/\s+/g, '') ||
          (f.title === find.title && f.fileOrUrl === find.fileOrUrl)
        );
        if (!dup) {
          combinedFindings.push(find);
        }
      }
    }

    if (aiReport.endpoints && Array.isArray(aiReport.endpoints)) {
      for (const end of aiReport.endpoints) {
        const dup = combinedEndpoints.some(e => 
          e.domain === end.domain && 
          e.path.split('?')[0] === end.path.split('?')[0]
        );
        if (!dup) {
          combinedEndpoints.push(end);
        }
      }
    }

    // Dynamically recompute scorecard across compiled findings for correctness
    const highVal = combinedFindings.filter(f => f.severity === 'high').length;
    const medVal = combinedFindings.filter(f => f.severity === 'medium').length;
    const lowVal = combinedFindings.filter(f => f.severity === 'low').length;
    const infoVal = combinedFindings.filter(f => f.severity === 'info').length;

    let score = 100 - (highVal * 18) - (medVal * 9) - (lowVal * 2);
    if (score < 5) score = 5;

    let grade = 'A';
    if (score < 60) grade = 'F';
    else if (score < 70) grade = 'D';
    else if (score < 80) grade = 'C';
    else if (score < 90) grade = 'B';

    // Detailed site lists for custom visualization in the react report UI
    const targetBreakdowns = scannedTargets.map(t => {
      const siteFindings = combinedFindings.filter(f => f.fileOrUrl.toLowerCase().includes(t.hostname.toLowerCase()));
      const siteHigh = siteFindings.filter(f => f.severity === 'high').length;
      const siteMed = siteFindings.filter(f => f.severity === 'medium').length;
      let siteScore = 100 - (siteHigh * 20) - (siteMed * 10);
      if (!t.success) siteScore = 0;
      if (siteScore < 5) siteScore = 5;

      let siteGrade = 'A';
      if (!t.success) siteGrade = 'N/A';
      else if (siteScore < 60) siteGrade = 'F';
      else if (siteScore < 70) siteGrade = 'D';
      else if (siteScore < 80) siteGrade = 'C';
      else if (siteScore < 90) siteGrade = 'B';

      return {
        url: t.url,
        hostname: t.hostname,
        success: t.success,
        error: t.error,
        score: t.success ? siteScore : 0,
        grade: siteGrade,
        findingsCount: siteFindings.length
      };
    });

    res.json({
      timestamp: new Date().toISOString(),
      targetName: `Batch: ${uniqueUrls.length} corporate sites`,
      targetType: 'url',
      findings: combinedFindings,
      endpoints: combinedEndpoints,
      scorecard: {
        score,
        grade,
        totalFindings: combinedFindings.length,
        highCount: highVal,
        mediumCount: medVal,
        lowCount: lowVal,
        infoCount: infoVal,
        assessmentSummary: aiReport.scorecard?.assessmentSummary || `Completed compliance auditing of ${scannedTargets.length} domains. Scanned index structures and security transports.`
      },
      complianceChecks: aiReport.complianceChecks || [
        { name: 'TLS Encryption Connection Matrix', passed: scannedTargets.every(t => !t.success || t.url.startsWith('https://')), description: 'Verify all requested landing links enforce complete SSL/TLS security protocols.' },
        { name: 'Unified Credential Escrow Audit', passed: highVal === 0, description: 'Audits the entire batch content for plain-text critical credentials.' },
        { name: 'Asset Security Alignment', passed: medVal === 0, description: 'Ensures external modular script nodes perform in absolute containment.' }
      ],
      targetBreakdowns
    });

  } catch (err: any) {
    console.error('Batch Endpoint Generation Failure:', err);
    res.status(500).json({ error: 'Failed compiling batch security report: ' + err.message });
  }
});

// Configure Vite or Serve SPA static files
async function serveApplication() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server starting securely on http://localhost:${PORT}`);
  });
}

serveApplication();
