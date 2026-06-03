export type Severity = 'high' | 'medium' | 'low' | 'info';

export type FindingType = 'secret' | 'endpoint' | 'libraries' | 'compliance';

export interface AuditFinding {
  id: string;
  type: FindingType;
  severity: Severity;
  title: string;
  description: string;
  fileOrUrl: string;
  lineNumber?: number;
  evidence: string; // The specific string/code chunk showing the finding
  resolution: string; // How to fix the issue
  category: string; // e.g. "AWS Cloud", "Google Maps Platform", "Stripe API", "Insecure Endpoint"
}

export interface EndpointFinding {
  id: string;
  domain: string;
  path: string;
  method: string;
  fileOrUrl: string;
  lineNumber?: number;
  category: string; // e.g., "Payment Gateway", "AI/ML API", "Internal API", "Analytics"
  secured: boolean; // Is it HTTPS/secured?
  usageExcerpt: string; // Code context
}

export interface SecurityScorecard {
  score: number; // 0 to 100
  grade: string; // A, B, C, D, F
  totalFindings: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  assessmentSummary: string;
}

export interface ScanResult {
  timestamp: string;
  targetName: string; // URL or File count
  targetType: 'code' | 'url';
  findings: AuditFinding[];
  endpoints: EndpointFinding[];
  scorecard: SecurityScorecard;
  complianceChecks: {
    name: string;
    passed: boolean;
    description: string;
    remediation?: string;
  }[];
}

export interface VaultItem {
  id: string;
  timestamp: string;
  title: string;
  category: string;
  secretValue: string;
  evidence: string;
  origin: string; // scanned domain or code file name
  severity: Severity;
  compromised: boolean; // has this been leaked in the public scans
  notes?: string;
}

