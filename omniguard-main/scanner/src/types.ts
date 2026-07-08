// Core types for the OmniGuard Security Scanner

export interface Finding {
  id: string;
  scanner: ScannerType;
  category: string;
  severity: Severity;
  title: string;
  description: string;
  evidence?: string;
  file_path: string;
  line_start?: number;
  line_end?: number;
  column_start?: number;
  column_end?: number;
  rule_id: string;
  rule_name: string;
  owasp: string[];
  cwe: string[];
  mitre: string[];
  cvss_score?: number;
  cvss_vector?: string;
  cve_id?: string;
  package_name?: string;
  package_version?: string;
  package_fixed_version?: string;
  remediation?: string;
  confidence_score: number;
  false_positive_likelihood: number;
  metadata: Record<string, unknown>;
}

export interface ScanResult {
  scanner: ScannerType;
  findings: Finding[];
  metadata: ScanMetadata;
  summary: ScanSummary;
}

export interface ScanMetadata {
  files_scanned: number;
  files_skipped: number;
  files_errored: number;
  duration_ms: number;
  scanner_version: string;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export type ScannerType =
  | 'secret'
  | 'dependency'
  | 'sast'
  | 'iac'
  | 'container'
  | 'license'
  | 'policy'
  | 'compliance'
  | 'ai';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Scanner {
  name(): string;
  type(): ScannerType;
  version(): string;
  supportedLanguages(): string[];
  supportedFiles(): string[];
  scan(context: ScanContext): Promise<ScanResult>;
  metadata(): ScannerMetadata;
}

export interface ScannerMetadata {
  name: string;
  version: string;
  type: ScannerType;
  languages: string[];
  filePatterns: string[];
  description: string;
}

export interface ScanContext {
  repositoryPath: string;
  basePath: string;
  files: ScannedFile[];
  options: ScanOptions;
  language?: string;
}

export interface ScannedFile {
  path: string;
  relativePath: string;
  content: string;
  size: number;
  language?: string;
  hash: string;
}

export interface ScanOptions {
  enabledScanners: ScannerType[];
  excludePatterns: string[];
  includePatterns: string[];
  failOn: Severity;
  maxFileSize: number;
  timeout: number;
  aiEnabled: boolean;
  aiModel?: 'haiku' | 'sonnet' | 'opus';
}

// Secret Detection Types
export interface SecretPattern {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  patterns: RegExp[];
  falsePositivePatterns?: RegExp[];
  entropyThreshold?: number;
  owasp: string[];
  cwe: string[];
  remediation: string;
}

// Dependency Scanning Types
export interface Dependency {
  name: string;
  version: string;
  ecosystem: string;
  filePath: string;
  line?: number;
}

export interface Vulnerability {
  id: string;
  packageName: string;
  affectedVersions: string;
  fixedVersions: string[];
  severity: Severity;
  cvss: number;
  title: string;
  description: string;
  references: string[];
  cwe: string[];
}

// SAST Types
export interface SASTRule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  languages: string[];
  patterns: RegexPattern[];
  owasp: string[];
  cwe: string[];
  mitre: string[];
  remediation: string;
}

export interface RegexPattern {
  pattern: string;
  message: string;
  severity?: Severity;
}

// IaC Types
export interface IaCMisconfiguration {
  id: string;
  resourceType: string;
  resourceName: string;
  filePath: string;
  line?: number;
  message: string;
  severity: Severity;
  remediation: string;
  references: string[];
}

// Container Types
export interface ContainerFinding {
  id: string;
  type: 'dockerfile' | 'image' | 'sbom';
  filePath: string;
  line?: number;
  message: string;
  severity: Severity;
  remediation: string;
}

// Policy Types
export interface Policy {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  enforcement: 'block' | 'warn' | 'audit';
  conditions: PolicyCondition[];
  remediation: string;
}

export interface PolicyCondition {
  field: string;
  operator: 'equals' | 'not_equals' | 'contains' | 'not_contains' | 'matches' | 'exists' | 'not_exists';
  value: string | string[] | RegExp;
  message: string;
}

// AI Analysis Types
export interface AIAnalysisRequest {
  type: 'classify' | 'explain' | 'remediate' | 'summarize';
  context: ScanContext;
  findings: Finding[];
  file?: ScannedFile;
}

export interface AIAnalysisResult {
  classification?: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  reasoning: string;
  explanation?: string;
  remediation?: string;
  references?: string[];
}

export interface AIProvider {
  name(): string;
  classify(request: AIAnalysisRequest): Promise<AIAnalysisResult>;
  explain(request: AIAnalysisRequest): Promise<AIAnalysisResult>;
  remediate(request: AIAnalysisRequest): Promise<AIAnalysisResult>;
  summarize(request: AIAnalysisRequest): Promise<AIAnalysisResult>;
}

// Compliance Mapping Types
export interface ComplianceMapping {
  framework: string;
  controlId: string;
  controlName: string;
  relevance: number;
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function severityWeight(severity: Severity): number {
  switch (severity) {
    case 'critical': return 10;
    case 'high': return 7;
    case 'medium': return 4;
    case 'low': return 2;
    case 'info': return 1;
  }
}

export function compareSeverity(a: Severity, b: Severity): number {
  return severityWeight(b) - severityWeight(a);
}
