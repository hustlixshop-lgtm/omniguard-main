// IaC Scanner - Infrastructure as Code Security Analysis
import { BaseScanner } from './base.js';
import { ScanContext, ScanResult, Finding, Severity } from '../types.js';

interface IaCRule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  resourceTypes: string[];
  check: (resource: Record<string, unknown>, resourceName: string) => { passed: boolean; message: string } | null;
  owasp: string[];
  cwe: string[];
  remediation: string;
}

export class IaCScanner extends BaseScanner {
  private rules: IaCRule[];

  constructor() {
    super();
    this.rules = this.loadIaCRules();
  }

  name(): string {
    return 'OmniGuard IaC Scanner';
  }

  type(): 'iac' {
    return 'iac';
  }

  version(): string {
    return '1.0.0';
  }

  supportedLanguages(): string[] {
    return ['terraform', 'hcl', 'yaml', 'json', 'dockerfile'];
  }

  supportedFiles(): string[] {
    return ['*.tf', '*.tf.json', '*.hcl', 'cloudformation.yaml', 'cloudformation.yml', '*.cloudformation.yaml', 'dockerfile', 'Dockerfile', 'docker-compose.yaml', 'docker-compose.yml', '*.yaml', '*.yml'];
  }

  async scan(context: ScanContext): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];
    let filesScanned = 0;
    let filesSkipped = 0;

    const files = this.filterFiles(context);

    for (const file of files) {
      filesScanned++;

      const fileType = this.detectFileType(file.relativePath);

      switch (fileType) {
        case 'terraform':
          findings.push(...this.scanTerraform(file.relativePath, file.content));
          break;
        case 'cloudformation':
          findings.push(...this.scanCloudFormation(file.relativePath, file.content));
          break;
        case 'dockerfile':
          findings.push(...this.scanDockerfile(file.relativePath, file.content));
          break;
        case 'kubernetes':
          findings.push(...this.scanKubernetes(file.relativePath, file.content));
          break;
      }
    }

    return {
      scanner: this.type(),
      findings,
      metadata: this.createMetadata(startTime, filesScanned, filesSkipped, 0),
      summary: this.createSummary(findings)
    };
  }

  private detectFileType(filePath: string): string {
    const lower = filePath.toLowerCase();
    if (lower.endsWith('.tf') || lower.endsWith('.tf.json') || lower.endsWith('.hcl')) {
      return 'terraform';
    }
    if (lower.includes('cloudformation') || lower.includes('sam-template')) {
      return 'cloudformation';
    }
    if (lower.includes('dockerfile') || lower.endsWith('.dockerfile')) {
      return 'dockerfile';
    }
    if (lower.includes('kubernetes') || lower.includes('k8s') || lower.includes('deployment') && lower.endsWith('.yaml') || lower.includes('helm')) {
      return 'kubernetes';
    }
    return 'terraform';
  }

  private scanTerraform(filePath: string, content: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    // Parse terraform blocks (simplified)
    const blocks = this.parseTerraformBlocks(content);

    for (const rule of this.rules) {
      for (const block of blocks) {
        if (rule.resourceTypes.includes(block.type) || rule.resourceTypes.includes('*')) {
          const result = rule.check(block.properties, block.name);
          if (result && !result.passed) {
            findings.push({
              id: this.generateId(),
              scanner: 'iac',
              category: rule.name,
              severity: rule.severity,
              title: `${rule.name} in ${block.type}.${block.name}`,
              description: result.message,
              file_path: filePath,
              line_start: block.lineStart,
              line_end: block.lineEnd,
              rule_id: rule.id,
              rule_name: rule.name,
              owasp: rule.owasp,
              cwe: rule.cwe,
              mitre: [],
              remediation: rule.remediation,
              confidence_score: 0.9,
              false_positive_likelihood: 0.1,
              metadata: {
                resource_type: block.type,
                resource_name: block.name
              }
            });
          }
        }
      }
    }

    // Pattern-based detection for Terraform
    const terraformPatterns = [
      { pattern: /public\s*=\s*true/g, rule: 'IAC-S3-001', message: 'S3 bucket set to public', severity: 'critical' as Severity },
      { pattern: /acl\s*=\s*['"]public-read['"]/g, rule: 'IAC-S3-002', message: 'S3 ACL allows public read', severity: 'critical' as Severity },
      { pattern: /skip_final_snapshot\s*=\s*true/g, rule: 'IAC-RDS-001', message: 'RDS skip final snapshot', severity: 'medium' as Severity },
      { pattern: /encrypt\s*=\s*false/g, rule: 'IAC-ENC-001', message: 'Encryption explicitly disabled', severity: 'high' as Severity },
      { pattern: /ssl_enforcement_enabled\s*=\s*false/g, rule: 'IAC-DB-001', message: 'SSL enforcement disabled', severity: 'high' as Severity },
      { pattern: /enable_logging\s*=\s*false/g, rule: 'IAC-LOG-001', message: 'Logging disabled', severity: 'medium' as Severity },
    ];

    for (const { pattern, rule, message, severity } of terraformPatterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: this.generateId(),
          scanner: 'iac',
          category: 'Terraform Misconfiguration',
          severity,
          title: message,
          description: `${message} in Terraform configuration.`,
          file_path: filePath,
          line_start: lineNumber,
          line_end: lineNumber,
          rule_id: rule,
          rule_name: message,
          owasp: ['A05:2021 - Security Misconfiguration'],
          cwe: ['CWE-16'],
          mitre: [],
          remediation: 'Review and update the configuration for security best practices.',
          confidence_score: 0.95,
          false_positive_likelihood: 0.05,
          metadata: { matched_pattern: pattern.source }
        });
      }
    }

    return findings;
  }

  private parseTerraformBlocks(content: string): Array<{ type: string; name: string; properties: Record<string, unknown>; lineStart: number; lineEnd: number }> {
    const blocks: Array<{ type: string; name: string; properties: Record<string, unknown>; lineStart: number; lineEnd: number }> = [];
    const lines = content.split('\n');

    const blockPattern = /^(\w+)\s+(?:["']?(\w+)["']?\s+)?{/;
    let currentBlock: { type: string; name: string; properties: Record<string, unknown>; lineStart: number; braces: number } | null = null;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      if (!currentBlock) {
        const match = blockPattern.exec(trimmed);
        if (match) {
          currentBlock = {
            type: match[1],
            name: match[2] || 'anonymous',
            properties: this.parseBlockProperties(lines.slice(i + 1).join('\n')),
            lineStart: i + 1,
            braces: 1
          };
        }
      } else {
        currentBlock.braces += (trimmed.match(/{/g) || []).length;
        currentBlock.braces -= (trimmed.match(/}/g) || []).length;

        if (currentBlock.braces === 0) {
          blocks.push({
            ...currentBlock,
            lineEnd: i + 1
          });
          currentBlock = null;
        }
      }
    }

    return blocks;
  }

  private parseBlockProperties(content: string): Record<string, unknown> {
    const props: Record<string, unknown> = {};
    const lines = content.split('\n');

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed === '}' || trimmed === '{') break;

      const match = /^(\w+)\s*=\s*(.+)$/.exec(trimmed);
      if (match) {
        let value: unknown = match[2].trim();
        // Simple value parsing
        if (value === 'true') value = true;
        else if (value === 'false') value = false;
        else if (/^\d+$/.test(value as string)) value = parseInt(value as string, 10);
        else if (/^['"].*['"]$/.test(value as string)) value = (value as string).slice(1, -1);

        props[match[1]] = value;
      }
    }

    return props;
  }

  private scanCloudFormation(filePath: string, content: string): Finding[] {
    const findings: Finding[] = [];

    try {
      const yaml = content.trim();
      // Simplified CloudFormation parsing
      if (yaml.includes('PublicAccessBlockConfiguration') && yaml.includes('BlockPublicAcls: false')) {
        findings.push(this.createCloudFormationFinding(filePath, 'IAC-CF-S3-001', 'S3 bucket allows public access', 'critical', 1));
      }

      if (yaml.includes('SecurityGroups') && yaml.includes('0.0.0.0/0')) {
        findings.push(this.createCloudFormationFinding(filePath, 'IAC-CF-SG-001', 'Security group allows 0.0.0.0/0 access', 'high', 1));
      }

      if (yaml.includes('PubliclyAccessible: true')) {
        findings.push(this.createCloudFormationFinding(filePath, 'IAC-CF-RDS-001', 'RDS instance is publicly accessible', 'critical', 1));
      }
    } catch {
      // YAML parse error
    }

    return findings;
  }

  private createCloudFormationFinding(filePath: string, ruleId: string, message: string, severity: Severity, line: number): Finding {
    return {
      id: this.generateId(),
      scanner: 'iac',
      category: 'CloudFormation Misconfiguration',
      severity,
      title: message,
      description: `${message} in CloudFormation template.`,
      file_path: filePath,
      line_start: line,
      line_end: line,
      rule_id: ruleId,
      rule_name: message,
      owasp: ['A05:2021 - Security Misconfiguration'],
      cwe: ['CWE-16'],
      mitre: [],
      remediation: 'Update CloudFormation template to follow security best practices.',
      confidence_score: 0.85,
      false_positive_likelihood: 0.1,
      metadata: {}
    };
  }

  private scanDockerfile(filePath: string, content: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      const trimmed = line.trim();

      // Check for root user
      if (trimmed === 'USER root' || (trimmed.startsWith('RUN') && trimmed.includes('root'))) {
        findings.push({
          id: this.generateId(),
          scanner: 'iac',
          category: 'Container Running as Root',
          severity: 'high',
          title: 'Container configured to run as root',
          description: 'Running containers as root user increases security risk.',
          file_path: filePath,
          line_start: index + 1,
          line_end: index + 1,
          rule_id: 'IAC-DOCKER-001',
          rule_name: 'Root User Detection',
          owasp: ['A05:2021 - Security Misconfiguration'],
          cwe: ['CWE-250'],
          mitre: [],
          remediation: 'Create a non-root user and use USER instruction to set it.',
          confidence_score: 0.9,
          false_positive_likelihood: 0.1,
          metadata: { instruction: trimmed }
        });
      }

      // Check for ADD usage (use COPY instead)
      if (trimmed.startsWith('ADD ')) {
        findings.push({
          id: this.generateId(),
          scanner: 'iac',
          category: 'ADD Instruction Usage',
          severity: 'low',
          title: 'Prefer COPY over ADD',
          description: 'ADD can extract archives and fetch from URLs. Use COPY for local files.',
          file_path: filePath,
          line_start: index + 1,
          line_end: index + 1,
          rule_id: 'IAC-DOCKER-002',
          rule_name: 'ADD Instruction Detection',
          owasp: [],
          cwe: [],
          mitre: [],
          remediation: 'Replace ADD with COPY unless you need automatic extraction.',
          confidence_score: 0.95,
          false_positive_likelihood: 0.05,
          metadata: {}
        });
      }

      // Check for secrets in ENV
      if (/ENV\s+\w*(?:SECRET|PASSWORD|TOKEN|KEY|API_KEY|PASS)\w*\s*=\s*\S+$/i.test(trimmed)) {
        findings.push({
          id: this.generateId(),
          scanner: 'iac',
          category: 'Secret in ENV',
          severity: 'critical',
          title: 'Secret exposed in ENV instruction',
          description: 'ENV instruction with potential secret value. Secrets should not be hardcoded.',
          file_path: filePath,
          line_start: index + 1,
          line_end: index + 1,
          rule_id: 'IAC-DOCKER-003',
          rule_name: 'Secret in Dockerfile',
          owasp: ['A07:2021 - Identification and Authentication Failures'],
          cwe: ['CWE-798'],
          mitre: [],
          remediation: 'Use Docker Secrets or environment variables at runtime.',
          confidence_score: 0.85,
          false_positive_likelihood: 0.15,
          metadata: {}
        });
      }

      // Check for exposed ports without restriction
      if (/EXPOSE\s+\d+/.test(trimmed)) {
        findings.push({
          id: this.generateId(),
          scanner: 'iac',
          category: 'Exposed Port',
          severity: 'info',
          title: 'Port exposed in Dockerfile',
          description: 'Consider if this port needs to be exposed. Document the service.',
          file_path: filePath,
          line_start: index + 1,
          line_end: index + 1,
          rule_id: 'IAC-DOCKER-004',
          rule_name: 'Port Exposure',
          owasp: [],
          cwe: [],
          mitre: [],
          remediation: 'Review if port exposure is necessary. Only expose required ports.',
          confidence_score: 0.9,
          false_positive_likelihood: 0.2,
          metadata: {}
        });
      }

      // Check for latest tag
      if (/FROM\s+\S+:latest/i.test(trimmed)) {
        findings.push({
          id: this.generateId(),
          scanner: 'iac',
          category: 'Latest Tag Usage',
          severity: 'medium',
          title: 'Base image uses :latest tag',
          description: 'Using :latest tag makes builds non-deterministic and can introduce vulnerabilities.',
          file_path: filePath,
          line_start: index + 1,
          line_end: index + 1,
          rule_id: 'IAC-DOCKER-005',
          rule_name: 'Latest Tag',
          owasp: ['A06:2021 - Vulnerable and Outdated Components'],
          cwe: ['CWE-1103'],
          mitre: [],
          remediation: 'Pin to a specific version tag for reproducible builds.',
          confidence_score: 0.95,
          false_positive_likelihood: 0.1,
          metadata: {}
        });
      }

      // Check for curl | bash patterns
      if (/RUN\s+curl\s+\S*\|\s*(?:sudo\s+)?bash/i.test(trimmed)) {
        findings.push({
          id: this.generateId(),
          scanner: 'iac',
          category: 'Unsafe Curl Usage',
          severity: 'high',
          title: 'Unsafe curl | bash pattern',
          description: 'Downloading and executing scripts directly is unsafe.',
          file_path: filePath,
          line_start: index + 1,
          line_end: index + 1,
          rule_id: 'IAC-DOCKER-006',
          rule_name: 'Unsafe Install',
          owasp: ['A01:2021 - Broken Access Control'],
          cwe: ['CWE-494'],
          mitre: [],
          remediation: 'Download, verify checksum, then execute. Prefer package managers.',
          confidence_score: 0.9,
          false_positive_likelihood: 0.1,
          metadata: {}
        });
      }
    });

    return findings;
  }

  private scanKubernetes(filePath: string, content: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      const trimmed = line.trim();

      if (trimmed.includes('privileged: true')) {
        findings.push({
          id: this.generateId(),
          scanner: 'iac',
          category: 'Privileged Container',
          severity: 'critical',
          title: 'Privileged container detected',
          description: 'Running containers in privileged mode gives full host access.',
          file_path: filePath,
          line_start: index + 1,
          line_end: index + 1,
          rule_id: 'IAC-K8S-001',
          rule_name: 'Privileged Container',
          owasp: ['A05:2021 - Security Misconfiguration'],
          cwe: ['CWE-250'],
          mitre: [],
          remediation: 'Remove privileged: true or use specific capabilities instead.',
          confidence_score: 0.95,
          false_positive_likelihood: 0.05,
          metadata: {}
        });
      }

      if (trimmed.includes('hostNetwork: true')) {
        findings.push({
          id: this.generateId(),
          scanner: 'iac',
          category: 'Host Network',
          severity: 'high',
          title: 'Container uses host network',
          description: 'hostNetwork: true shares the host\'s network namespace.',
          file_path: filePath,
          line_start: index + 1,
          line_end: index + 1,
          rule_id: 'IAC-K8S-002',
          rule_name: 'Host Network',
          owasp: ['A05:2021 - Security Misconfiguration'],
          cwe: ['CWE-250'],
          mitre: [],
          remediation: 'Set hostNetwork: false.',
          confidence_score: 0.9,
          false_positive_likelihood: 0.1,
          metadata: {}
        });
      }

      if (trimmed.includes('runAsUser: 0') || trimmed.includes('runAsRoot: true')) {
        findings.push({
          id: this.generateId(),
          scanner: 'iac',
          category: 'Root User',
          severity: 'high',
          title: 'Container runs as root',
          description: 'Security context specifies root user (UID 0).',
          file_path: filePath,
          line_start: index + 1,
          line_end: index + 1,
          rule_id: 'IAC-K8S-003',
          rule_name: 'Root User',
          owasp: ['A05:2021 - Security Misconfiguration'],
          cwe: ['CWE-250'],
          mitre: [],
          remediation: 'Set runAsUser to non-zero value and runAsNonRoot: true.',
          confidence_score: 0.9,
          false_positive_likelihood: 0.1,
          metadata: {}
        });
      }

      if (trimmed.includes('hostPID: true')) {
        findings.push({
          id: this.generateId(),
          scanner: 'iac',
          category: 'Host PID',
          severity: 'high',
          title: 'Container uses host PID namespace',
          description: 'hostPID: true allows seeing all processes on host.',
          file_path: filePath,
          line_start: index + 1,
          line_end: index + 1,
          rule_id: 'IAC-K8S-004',
          rule_name: 'Host PID',
          owasp: ['A05:2021 - Security Misconfiguration'],
          cwe: ['CWE-250'],
          mitre: [],
          remediation: 'Set hostPID: false.',
          confidence_score: 0.9,
          false_positive_likelihood: 0.1,
          metadata: {}
        });
      }
    });

    return findings;
  }

  private loadIaCRules(): IaCRule[] {
    return [
      {
        id: 'IAC-SEC-001',
        name: 'S3 Public Access',
        description: 'S3 bucket should not be public',
        severity: 'critical',
        resourceTypes: ['aws_s3_bucket'],
        check: (props, _name) => {
          if (props.public === true || props.acl === 'public-read' || props.acl === 'public-read-write') {
            return { passed: false, message: 'S3 bucket is configured to be public' };
          }
          return { passed: true, message: '' };
        },
        owasp: ['A01:2021 - Broken Access Control'],
        cwe: ['CWE-284'],
        remediation: 'Set public = false and use a specific IAM policy for controlled access.'
      }
    ];
  }
}
