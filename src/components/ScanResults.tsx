import { useState, useEffect } from 'react';
import { ScanResult, AuditFinding, EndpointFinding, VaultItem } from '../types';
import { 
  ShieldCheck, ShieldAlert, AlertTriangle, Info, 
  Lock, Eye, EyeOff, Globe, Server, Code,
  Download, Copy, CheckCircle2, ChevronRight, CornerDownRight, ExternalLink
} from 'lucide-react';

interface ScanResultsProps {
  result: ScanResult;
}

export default function ScanResults({ result }: ScanResultsProps) {
  const [activeResultsTab, setActiveResultsTab] = useState<'summary' | 'secrets' | 'endpoints' | 'remediation'>('summary');
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, boolean>>({});
  const [copiedReport, setCopiedReport] = useState(false);
  const [escrowedIds, setEscrowedIds] = useState<Record<string, boolean>>({});

  useEffect(() => {
    // Sync current vault state with displayed buttons
    const loaded = localStorage.getItem('sentry_keys_vault');
    if (loaded) {
      try {
        const vault: VaultItem[] = JSON.parse(loaded);
        const mapped: Record<string, boolean> = {};
        vault.forEach(item => {
          // If title matches finding or secret matches evidence, mark as cataloged
          mapped[item.id] = true;
          // also map by custom pattern
          mapped[item.title] = true;
        });
        setEscrowedIds(mapped);
      } catch (err) {}
    }
  }, []);

  const handleEscrow = (finding: AuditFinding) => {
    const loaded = localStorage.getItem('sentry_keys_vault');
    let currentVault: VaultItem[] = [];
    if (loaded) {
      try {
        currentVault = JSON.parse(loaded);
      } catch (err) {}
    }

    // Check if already escrowed
    if (currentVault.some(v => v.evidence === finding.evidence)) {
      setEscrowedIds(prev => ({ ...prev, [finding.id]: true }));
      return;
    }

    const newItem: VaultItem = {
      id: `vault-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      title: finding.title,
      category: finding.category,
      secretValue: finding.evidence,
      evidence: finding.evidence,
      origin: finding.fileOrUrl,
      severity: finding.severity,
      compromised: true,
      notes: 'Automatically escrowed from active compliance run.'
    };

    const nextVault = [newItem, ...currentVault];
    localStorage.setItem('sentry_keys_vault', JSON.stringify(nextVault));
    setEscrowedIds(prev => ({ ...prev, [finding.id]: true }));
  };


  const { scorecard, findings, endpoints, complianceChecks, targetName, targetType } = result;

  // Toggle key visibility in vault
  const toggleSecretReveal = (id: string) => {
    setRevealedSecrets((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  // Helper colors for Severity
  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'high':
        return (
          <span className="inline-flex items-center space-x-1 rounded-full bg-rose-50 border border-rose-200 px-2.5 py-1 text-xs font-semibold text-rose-700 animate-pulse">
            <ShieldAlert className="h-3.5 w-3.5" />
            <span className="uppercase">High Risk</span>
          </span>
        );
      case 'medium':
        return (
          <span className="inline-flex items-center space-x-1 rounded-full bg-amber-50 border border-amber-200 px-2.5 py-1 text-xs font-semibold text-amber-700">
            <AlertTriangle className="h-3.5 w-3.5" />
            <span className="uppercase">Medium Risk</span>
          </span>
        );
      case 'low':
        return (
          <span className="inline-flex items-center space-x-1 rounded-full bg-blue-50 border border-blue-200 px-2.5 py-1 text-xs font-semibold text-blue-700">
            <Info className="h-3.5 w-3.5" />
            <span className="uppercase">Low Risk</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center space-x-1 rounded-full bg-slate-50 border border-slate-200 px-2.5 py-1 text-xs font-semibold text-slate-700">
            <Info className="h-3.5 w-3.5" />
            <span className="uppercase">Info</span>
          </span>
        );
    }
  };

  // Helper colors for Scorecard Score
  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-emerald-600 bg-emerald-50 border-emerald-200';
    if (score >= 75) return 'text-amber-600 bg-amber-50 border-amber-200';
    return 'text-rose-600 bg-rose-50 border-rose-200';
  };

  // Compile full Corporate Compliance Audit Report in Markdown
  const compileMarkdownReport = () => {
    const timestamp = new Date(result.timestamp).toLocaleString();
    let md = `# Security Audit Compliance Report\n`;
    md += `**Target Workspace**: \`${targetName}\` (${targetType.toUpperCase()})\n`;
    md += `**Audit Timestamp**: ${timestamp}\n`;
    md += `**Final Grade**: ${scorecard.grade} (Security score: ${scorecard.score}/100)\n`;
    md += `========================================================================\n\n`;
    md += `## 1. Executive Summary\n`;
    md += `${scorecard.assessmentSummary}\n\n`;
    md += `- **High Risk Vulnerabilities**: ${scorecard.highCount}\n`;
    md += `- **Medium Risk Vulnerabilities**: ${scorecard.mediumCount}\n`;
    md += `- **Low Risk Vulnerabilities**: ${scorecard.lowCount}\n\n`;
    
    md += `## 2. Compliance Checklist Status\n`;
    complianceChecks.forEach((chk) => {
      md += - `[${chk.passed ? 'X' : ' '}] ${chk.name}: ${chk.passed ? 'PASSED' : 'FAILED'} - ${chk.description}\n`;
    });
    md += `\n`;

    md += `## 3. Discovered Programmatic Keys & Secrets (${findings.length})\n`;
    if (findings.length === 0) {
      md += `*Excellent! No hardcoded keys or unmasked credentials detected statically.*\n`;
    } else {
      findings.forEach((find, i) => {
        md += `### [${find.severity.toUpperCase()}] ${find.title}\n`;
        md += `- **Platform/Category**: ${find.category}\n`;
        md += `- **Location**: ${find.fileOrUrl}${find.lineNumber ? ` (Line ${find.lineNumber})` : ''}\n`;
        md += `- **Threat Context**: ${find.description}\n`;
        md += `- **Evidence Excerpt**: \`${find.evidence}\`\n`;
        md += `- **Remediation**: ${find.resolution}\n\n`;
      });
    }

    md += `## 4. Discovered API Endpoints & Routes (${endpoints.length})\n`;
    if (endpoints.length === 0) {
      md += `*No external API network query routes discovered in scanned assets.*\n`;
    } else {
      endpoints.forEach((end, i) => {
        md += `- **Domain**: \`${end.domain}\`\n`;
        md += `  - Path: \`${end.path}\` | Method: \`${end.method}\`\n`;
        md += `  - Service Type: ${end.category} | Secured (TLS/SSL): ${end.secured ? 'YES' : 'NO'}\n`;
        md += `  - Context file: \`${end.fileOrUrl}\` (Line ${end.lineNumber || 'client-load'})\n\n`;
      });
    }
    
    md += `------------------------------------------------------------------------\n`;
    md += `*Report processed and structured securely via API Sentinel Compliance Engine.*`;
    return md;
  };

  const copyToClipboard = () => {
    const mdReport = compileMarkdownReport();
    navigator.clipboard.writeText(mdReport);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 2000);
  };

  const downloadJsonReport = () => {
    const jsonStr = JSON.stringify(result, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `comply_report_${targetName.replace(/\./g, '_')}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Target Title Banner */}
      <div className="flex flex-col justify-between space-y-4 rounded-xl border border-slate-200 bg-slate-900 p-6 text-white sm:flex-row sm:items-center sm:space-y-0 shadow-md">
        <div>
          <span className="inline-flex items-center rounded-md bg-indigo-500/15 px-2.5 py-1 text-xs font-semibold text-indigo-300 border border-indigo-500/20 uppercase tracking-wide">
            {targetType === 'url' ? 'Web Sniff Scan' : 'Workspace SAST'}
          </span>
          <h2 className="mt-2 text-xl font-bold tracking-tight sm:text-2xl">
            {targetName}
          </h2>
          <p className="text-xs text-slate-400 mt-1 font-medium">
            Scan completed: {new Date(result.timestamp).toLocaleString()}
          </p>
        </div>

        {/* Action Panel: Copy MD, Download JSON */}
        <div className="flex items-center space-x-3 self-start sm:self-center">
          <button
            onClick={copyToClipboard}
            className="flex items-center space-x-2 rounded-xl bg-slate-800 border border-slate-700 px-4 py-2.5 text-xs font-bold text-slate-200 hover:bg-slate-700 transition-colors cursor-pointer"
          >
            {copiedReport ? (
              <>
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                <span>Copied!</span>
              </>
            ) : (
              <>
                <Copy className="h-3.5 w-3.5" />
                <span>Copy Markdown</span>
              </>
            )}
          </button>

          <button
            onClick={downloadJsonReport}
            className="flex items-center space-x-2 rounded-xl bg-slate-800 border border-slate-700 px-4 py-2.5 text-xs font-bold text-slate-200 hover:bg-slate-700 transition-colors cursor-pointer"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Download JSON</span>
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-200">
        <button
          onClick={() => setActiveResultsTab('summary')}
          className={`border-b-2 px-5 py-3 text-sm font-bold transition-all duration-205 ${
            activeResultsTab === 'summary'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:border-slate-300 hover:text-slate-800'
          }`}
        >
          Executive Summary
        </button>

        <button
          onClick={() => setActiveResultsTab('secrets')}
          className={`relative border-b-2 px-5 py-3 text-sm font-bold transition-all duration-205 ${
            activeResultsTab === 'secrets'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:border-slate-300 hover:text-slate-800'
          }`}
        >
          API Key Vault & Leaks
          {findings.length > 0 && (
            <span className="absolute -top-1 -right-1 flex h-4.5 w-4.5 items-center justify-center rounded-full bg-rose-500 text-[10px] font-bold text-white shadow-xs">
              {findings.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveResultsTab('endpoints')}
          className={`relative border-b-2 px-5 py-3 text-sm font-bold transition-all duration-205 ${
            activeResultsTab === 'endpoints'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:border-slate-300 hover:text-slate-800'
          }`}
        >
          Discovered API Pathsons
          {endpoints.length > 0 && (
            <span className="absolute -top-1 -right-1 flex h-4.5 w-4.5 items-center justify-center rounded-full bg-indigo-500 text-[10px] font-bold text-white shadow-xs">
              {endpoints.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveResultsTab('remediation')}
          className="border-b-2 px-5 py-3 text-sm font-bold border-transparent text-slate-500 hover:border-slate-300 hover:text-slate-800 transition-all duration-205"
        >
          Remediation priorities
        </button>
      </div>

      {/* Tab Panels */}
      <div className="space-y-6">
        {/* EXECUTIVE SUMMARY */}
        {activeResultsTab === 'summary' && (
          <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
            {/* Left Metrics */}
            <div className="md:col-span-1 space-y-6">
              {/* Scorecard Gauge */}
              <div className="rounded-xl border border-slate-200 bg-white p-6 text-center shadow-xs">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500">
                  Security Rating Score
                </h3>
                <div className="mt-4 flex items-center justify-center">
                  <div className={`relative flex h-32 w-32 items-center justify-center rounded-full border-4 border-slate-100 shadow-inner md:h-36 md:w-36`}>
                    <svg className="absolute inset-0 h-full w-full transform -rotate-90" viewBox="0 0 100 100">
                      <circle
                        cx="50"
                        cy="50"
                        r="45"
                        fill="transparent"
                        stroke="#f1f5f9"
                        strokeWidth="5"
                      />
                      <circle
                        cx="50"
                        cy="50"
                        r="45"
                        fill="transparent"
                        stroke={scorecard.score >= 90 ? '#10b981' : scorecard.score >= 75 ? '#f59e0b' : '#f43f5e'}
                        strokeWidth="5"
                        strokeDasharray={2 * Math.PI * 45}
                        strokeDashoffset={2 * Math.PI * 45 * (1 - scorecard.score / 100)}
                        strokeLinecap="round"
                        className="transition-all duration-1000 ease-out"
                      />
                    </svg>
                    <div className="text-center z-10">
                      <span className="block text-4xl font-extrabold tracking-tight text-slate-900 md:text-5xl">
                        {scorecard.grade}
                      </span>
                      <span className="text-xs font-semibold text-slate-500">
                        {scorecard.score}/100 Grade
                      </span>
                    </div>
                  </div>
                </div>
                <p className="mt-4 text-xs font-semibold text-slate-600">
                  Threat exposure mitigation status
                </p>
              </div>

              {/* Severity Counts Grid */}
              <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs grid grid-cols-2 gap-4">
                <div className="rounded-lg bg-rose-50/50 border border-rose-100/60 p-3 text-center">
                  <span className="block text-xs font-bold uppercase text-rose-600">Critical</span>
                  <span className="mt-1 block text-2xl font-extrabold text-rose-950">{scorecard.highCount}</span>
                </div>
                <div className="rounded-lg bg-amber-50/50 border border-amber-100/60 p-3 text-center">
                  <span className="block text-xs font-bold uppercase text-amber-600">Medium</span>
                  <span className="mt-1 block text-2xl font-extrabold text-amber-950">{scorecard.mediumCount}</span>
                </div>
                <div className="rounded-lg bg-blue-50/50 border border-blue-100/60 p-3 text-center">
                  <span className="block text-xs font-bold uppercase text-blue-600">Minor / Low</span>
                  <span className="mt-1 block text-2xl font-extrabold text-blue-950">{scorecard.lowCount}</span>
                </div>
                <div className="rounded-lg bg-slate-50 border border-slate-100 p-3 text-center">
                  <span className="block text-xs font-bold uppercase text-slate-600">Info Log</span>
                  <span className="mt-1 block text-2xl font-extrabold text-slate-950">{scorecard.infoCount}</span>
                </div>
              </div>
            </div>

            {/* Right Cognitive Assessment Summary */}
            <div className="md:col-span-2 space-y-6">
              <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-xs space-y-5">
                <h3 className="text-sm font-bold tracking-tight text-slate-900 flex items-center space-x-2 border-b border-slate-100 pb-3">
                  <ShieldCheck className="h-4.5 w-4.5 text-indigo-600" />
                  <span>Cognitive Compliance Evaluation</span>
                </h3>
                <p className="text-sm text-slate-700 leading-relaxed font-normal whitespace-pre-wrap">
                  {scorecard.assessmentSummary}
                </p>

                {/* Compliance Checking checklist */}
                <div className="pt-3 space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500">
                    SLA Compliance Guidelines Status
                  </h4>
                  <div className="space-y-2.5">
                    {complianceChecks.map((chk, i) => (
                      <div
                        key={`${chk.name}-${i}`}
                        className="flex items-start space-x-3 rounded-lg border border-slate-100 bg-slate-50/60 p-3"
                      >
                        {chk.passed ? (
                          <div className="flex h-5 w-5 items-center justify-center rounded-full bg-emerald-100 text-emerald-700 shrink-0 mt-0.5">
                            <CheckCircle2 className="h-3.5 w-3.5" />
                          </div>
                        ) : (
                          <div className="flex h-5 w-5 items-center justify-center rounded-full bg-rose-100 text-rose-700 shrink-0 mt-0.5">
                            <ShieldAlert className="h-3.5 w-3.5" />
                          </div>
                        )}
                        <div>
                          <h5 className="text-xs font-bold text-slate-900">{chk.name}</h5>
                          <p className="mt-0.5 text-xs text-slate-600">{chk.description}</p>
                          {!chk.passed && chk.remediation && (
                            <p className="mt-1.5 text-xs text-rose-700 font-semibold flex items-center">
                              <CornerDownRight className="h-3 w-3 mr-1" />
                              Fix: {chk.remediation}
                            </p>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* SECRETS VAULT TABLE */}
        {activeResultsTab === 'secrets' && (
          <div className="rounded-xl border border-slate-200 bg-white shadow-xs overflow-hidden">
            <div className="bg-slate-50 border-b border-slate-200 px-6 py-4 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
                  <Lock className="h-4 w-4 text-indigo-600" />
                  <span>Programmatic Assets Secrets Discovery Vault</span>
                </h3>
                <p className="text-xs text-slate-500 mt-0.5 font-medium">
                  Matches on-page hardcoded Google credentials, cloud system storage connections, client databases and keys.
                </p>
              </div>
              <span className="rounded-md bg-slate-100 px-2.5 py-1 text-xs font-bold text-slate-700">
                Found {findings.length} Finding(s)
              </span>
            </div>

            {findings.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
                <ShieldCheck className="h-12 w-12 text-emerald-500 mb-2" />
                <h4 className="text-sm font-bold text-slate-950">No API Key Leaks Identified</h4>
                <p className="max-w-md mt-1 text-xs text-slate-500">
                  Static evaluation completed. This source code and public assets do not contain typical exposed credentials or database URL secrets.
                </p>
              </div>
            ) : (
              <div className="divide-y divide-slate-150">
                {findings.map((find) => (
                  <div key={find.id} className="p-6 space-y-4 hover:bg-slate-50/50 transition-colors">
                    <div className="flex flex-col justify-between space-y-3 sm:flex-row sm:items-center sm:space-y-0">
                      <div className="space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <h4 className="text-sm font-bold text-slate-900">{find.title}</h4>
                          {getSeverityBadge(find.severity)}
                          <span className="rounded-md bg-slate-100 px-2.5 py-0.5 text-[10px] font-semibold text-slate-600 border border-slate-200/50">
                            {find.category}
                          </span>
                        </div>
                        <p className="text-xs font-semibold text-slate-500 flex items-center">
                          <Server className="h-3.5 w-3.5 mr-1.5 text-slate-400" />
                          <span>File: {find.fileOrUrl} {find.lineNumber ? `(Line ${find.lineNumber})` : ''}</span>
                        </p>
                      </div>

                      <div className="shrink-0">
                        <button
                          type="button"
                          onClick={() => handleEscrow(find)}
                          className={`flex items-center space-x-1 px-3 py-1.5 rounded-lg text-xs font-bold border transition ${
                            escrowedIds[find.id] || escrowedIds[find.title]
                              ? 'bg-emerald-50 text-emerald-700 border-emerald-200 cursor-default'
                              : 'bg-indigo-600 hover:bg-indigo-700 text-white border-indigo-600 cursor-pointer shadow-xs'
                          }`}
                        >
                          <Lock className="h-3 w-3" />
                          <span>{escrowedIds[find.id] || escrowedIds[find.title] ? 'Escrowed to Vault' : 'Escrow to Vault'}</span>
                        </button>
                      </div>
                    </div>

                    <p className="text-xs text-slate-700 font-normal leading-relaxed">
                      {find.description}
                    </p>

                    {/* Excerpt with reveal key */}
                    <div className="rounded-lg border border-slate-200 bg-slate-900/95 shadow-sm overflow-hidden font-mono text-[11px]">
                      <div className="bg-slate-800 px-4 py-2 flex items-center justify-between text-slate-400 select-none">
                        <span className="font-bold flex items-center text-[10px] uppercase tracking-wider">
                          <Code className="h-3 w-3 mr-1 text-indigo-400" />
                          Code Excerpt Sniff
                        </span>
                        <button
                          onClick={() => toggleSecretReveal(find.id)}
                          className="flex items-center space-x-1 hover:text-slate-200 focus:outline text-[11px] font-bold cursor-pointer"
                        >
                          {revealedSecrets[find.id] ? (
                            <>
                              <EyeOff className="h-3 w-3" />
                              <span>Mask Secret</span>
                            </>
                          ) : (
                            <>
                              <Eye className="h-3 w-3" />
                              <span>Reveal Raw</span>
                            </>
                          )}
                        </button>
                      </div>
                      <div className="p-4 text-slate-300 overflow-x-auto whitespace-pre">
                        <code>
                          {revealedSecrets[find.id] 
                            ? find.evidence 
                            : find.evidence.replace(
                                /(AIzaSy[A-Za-z0-9_-]{10})[A-Za-z0-9_-]{25}/g, '$1*************************'
                              ).replace(
                                /(sk_live_[0-9a-zA-Z]{5})[0-9a-zA-Z]{19,}/g, '$1*************************'
                              ).replace(
                                /(AKIA[0-9A-Z]{4})[0-9A-Z]{12}/g, '$1************'
                              ).replace(
                                /(:[A-Za-z0-9_.-]{4})[A-Za-z0-9_.-]{6,}(@postgresql|@amazonaws)/g, '$1******$2'
                              )
                          }
                        </code>
                      </div>
                    </div>

                    {/* Remediation Advice bubble */}
                    <div className="rounded-lg bg-emerald-50/50 border border-emerald-100/80 p-3.5 font-sans">
                      <h5 className="text-xs font-bold text-emerald-900 flex items-center">
                        <ShieldCheck className="h-4 w-4 mr-1.5 text-emerald-600" />
                        Remediation Action Plan
                      </h5>
                      <p className="mt-1 text-xs text-emerald-800 leading-relaxed font-normal">
                        {find.resolution}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* COMMUNICATION ROUTER TAB */}
        {activeResultsTab === 'endpoints' && (
          <div className="rounded-xl border border-slate-200 bg-white shadow-xs overflow-hidden">
            <div className="bg-slate-50 border-b border-slate-200 px-6 py-4 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
                  <Globe className="h-4 w-4 text-indigo-600" />
                  <span>Programmatic Discovered Networks & API Paths</span>
                </h3>
                <p className="text-xs text-slate-500 mt-0.5 font-medium">
                  Audits corporate routing parameters, verifying SSL certificate connections and destination servers.
                </p>
              </div>
              <span className="rounded-md bg-indigo-50 border border-indigo-200 px-2.5 py-1 text-xs font-bold text-indigo-700">
                {endpoints.length} Endpoint(s) Loaded
              </span>
            </div>

            {endpoints.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
                <Globe className="h-12 w-12 text-slate-300 mb-2" />
                <h4 className="text-sm font-bold text-slate-950">No Programmatic API Paths Found</h4>
                <p className="max-w-md mt-1 text-xs text-slate-500">
                  This static run did not locate standard external endpoint URLs inside the audited elements.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left font-sans text-xs border-collapse">
                  <thead>
                    <tr className="bg-slate-50/70 border-b border-slate-100 uppercase text-[10px] font-bold text-slate-500 tracking-wider">
                      <th className="px-6 py-3">Host Domain</th>
                      <th className="px-6 py-3">API Route Path</th>
                      <th className="px-6 py-3">Service Profile</th>
                      <th className="px-6 py-3 text-center">Transport Security</th>
                      <th className="px-6 py-3">File Context Location</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 text-slate-700">
                    {endpoints.map((end) => (
                      <tr key={end.id} className="hover:bg-slate-50/40 transition-colors">
                        <td className="px-6 py-4 font-bold text-slate-900">
                          <span className="flex items-center space-x-2">
                            <ChevronRight className="h-3 w-3 text-indigo-500 shrink-0" />
                            <span className="truncate max-w-[180px]">{end.domain}</span>
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] text-slate-800 select-all truncate max-w-[200px] inline-block">
                            {end.method} {end.path}
                          </code>
                        </td>
                        <td className="px-6 py-4 font-semibold text-slate-500">
                          {end.category}
                        </td>
                        <td className="px-6 py-4 text-center">
                          {end.secured ? (
                            <span className="inline-flex items-center rounded-md bg-emerald-50 px-2 py-0.5 font-bold text-emerald-700 border border-emerald-150 text-[10px]">
                              SSL - HTTPS
                            </span>
                          ) : (
                            <span className="inline-flex items-center rounded-md bg-rose-50 px-2 py-0.5 font-bold text-rose-700 border border-rose-150 text-[10px] animate-pulse">
                              PLAIN - HTTP
                            </span>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-slate-500 font-medium">
                          {end.fileOrUrl} {end.lineNumber ? `(Line ${end.lineNumber})` : ''}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* REMEDIATION TAB */}
        {activeResultsTab === 'remediation' && (
          <div className="space-y-6">
            <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-xs space-y-4">
              <h3 className="text-sm font-bold tracking-tight text-slate-900 flex items-center space-x-2 border-b border-slate-100 pb-3">
                <Lock className="h-4.5 w-4.5 text-indigo-600" />
                <span>Fix Guidelines & Security Priorities</span>
              </h3>
              
              <div className="space-y-4 text-sm text-slate-700">
                <div className="p-4 border-l-4 border-rose-500 bg-rose-50/40 rounded-r-lg space-y-1">
                  <span className="font-bold text-rose-900 uppercase text-xs tracking-wider">Priority 1: Rotate Hardcoded Keys immediately</span>
                  <p className="text-xs text-rose-800 leading-relaxed leading-relaxed font-normal">
                    Exposed private credentials to live clients allows contractors or malicious network sniffers to exhaust usage quotas or download confidential DB ledgers. Inactivate the old keys inside Cloud admin consoles (AWS, Stripe, Firebase) and create fresh authorization profiles.
                  </p>
                </div>

                <div className="p-4 border-l-4 border-indigo-500 bg-indigo-50/40 rounded-r-lg space-y-1">
                  <span className="font-bold text-indigo-900 uppercase text-xs tracking-wider">Priority 2: Migrate keys to Container Runtime Environments</span>
                  <p className="text-xs text-indigo-800 leading-relaxed leading-relaxed font-normal">
                    Secrets must reside inside system environments (e.g. <code>.env</code> file elements, AWS Secrets Manager, or Google Cloud Secret Manager) rather than raw programmatic codes. Reference keys dynamically in Node via <code>process.env.API_KEY</code>.
                  </p>
                </div>

                <div className="p-4 border-l-4 border-blue-500 bg-blue-50/40 rounded-r-lg space-y-1">
                  <span className="font-bold text-blue-900 uppercase text-xs tracking-wider">Priority 3: Restrict public credential scopes</span>
                  <p className="text-xs text-blue-800 leading-relaxed font-normal">
                    Where credentials must be client-facing, set rigorous restriction profiles. For example, configure HTTP referrers on Google Maps Platform keys to allow API calls exclusively coming from your official corporate top-level domain.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
