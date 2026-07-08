// Secret Detection Scanner - Real implementation
import { BaseScanner } from './base.js';
import { ScanContext, ScanResult, Finding, SecretPattern, Severity } from '../types.js';

export class SecretScanner extends BaseScanner {
  private patterns: SecretPattern[];

  constructor() {
    super();
    this.patterns = this.loadSecretPatterns();
  }

  name(): string {
    return 'OmniGuard Secret Scanner';
  }

  type(): 'secret' {
    return 'secret';
  }

  version(): string {
    return '1.0.0';
  }

  supportedLanguages(): string[] {
    return ['*']; // Scan all languages for secrets
  }

  supportedFiles(): string[] {
    return ['*']; // Scan all files
  }

  async scan(context: ScanContext): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];
    let filesScanned = 0;
    let filesSkipped = 0;

    const files = this.filterFiles(context);

    for (const file of files) {
      // Skip binary files and very large files
      if (this.isBinary(file.content) || file.size > context.options.maxFileSize) {
        filesSkipped++;
        continue;
      }

      filesScanned++;
      const fileFindings = this.scanFile(file.relativePath, file.content);
      findings.push(...fileFindings);
    }

    return {
      scanner: this.type(),
      findings,
      metadata: this.createMetadata(startTime, filesScanned, filesSkipped, 0),
      summary: this.createSummary(findings)
    };
  }

  private scanFile(filePath: string, content: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    for (const pattern of this.patterns) {
      for (const regex of pattern.patterns) {
        let match;
        const globalRegex = new RegExp(regex.source, regex.flags + 'g');

        while ((match = globalRegex.exec(content)) !== null) {
          // Check for false positives
          if (pattern.falsePositivePatterns) {
            const isFalsePositive = pattern.falsePositivePatterns.some(fp => {
              fp.lastIndex = 0;
              return fp.test(match[0]);
            });
            if (isFalsePositive) continue;
          }

          // Check entropy if threshold is set
          if (pattern.entropyThreshold && pattern.entropyThreshold > 0) {
            const entropy = this.calculateEntropy(match[0]);
            if (entropy < pattern.entropyThreshold) continue;
          }

          // Find line number
          const beforeMatch = content.substring(0, match.index);
          const lineNumber = beforeMatch.split('\n').length;
          const line = lines[lineNumber - 1]?.trim() || '';

          findings.push({
            id: this.generateId(),
            scanner: 'secret',
            category: pattern.name,
            severity: pattern.severity,
            title: `${pattern.name} detected`,
            description: pattern.description,
            evidence: this.maskSecret(match[0]),
            file_path: filePath,
            line_start: lineNumber,
            line_end: lineNumber,
            rule_id: pattern.id,
            rule_name: pattern.name,
            owasp: pattern.owasp,
            cwe: pattern.cwe,
            mitre: [],
            remediation: pattern.remediation,
            confidence_score: this.calculateConfidence(match[0], pattern),
            false_positive_likelihood: this.estimateFalsePositive(match[0], pattern, line),
            metadata: {
              matched_pattern: pattern.id,
              match_length: match[0].length
            }
          });
        }
      }
    }

    return findings;
  }

  private loadSecretPatterns(): SecretPattern[] {
    return [
      // AWS Keys
      {
        id: 'SECRET-AWS-001',
        name: 'AWS Access Key ID',
        description: 'AWS Access Key ID detected. This key can be used to access your AWS account.',
        severity: 'critical',
        patterns: [/(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g],
        falsePositivePatterns: [/(EXAMPLE|SAMPLE|TEST|YOUR_)/i],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Rotate the compromised key immediately in AWS IAM console.\n2. Use AWS Secrets Manager or environment variables.\n3. Never commit credentials to source control.\n4. Add key to .gitignore and consider using git-secrets or pre-commit hooks.'
      },
      {
        id: 'SECRET-AWS-002',
        name: 'AWS Secret Access Key',
        description: 'AWS Secret Access Key detected. This key provides full access to your AWS resources.',
        severity: 'critical',
        patterns: [/[A-Za-z0-9/+=]{40}/g],
        falsePositivePatterns: [/(EXAMPLE|SAMPLE|TEST|YOUR_|xxxxxx)/i],
        entropyThreshold: 4.5,
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Rotate the secret key immediately via AWS IAM.\n2. Use AWS Secrets Manager for secret storage.\n3. Never embed secrets in code or config files.'
      },

      // GitHub Tokens
      {
        id: 'SECRET-GITHUB-001',
        name: 'GitHub Personal Access Token',
        description: 'GitHub Personal Access Token detected. This token can be used to access repositories.',
        severity: 'critical',
        patterns: [/ghp_[A-Za-z0-9]{36}/g, /gho_[A-Za-z0-9]{36}/g, /ghu_[A-Za-z0-9]{36}/g, /ghs_[A-Za-z0-9]{36}/g, /ghr_[A-Za-z0-9]{36}/g],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Revoke the token immediately in GitHub Settings > Developer settings > Personal access tokens.\n2. Store tokens in environment variables or a secrets manager.\n3. Use GitHub Apps for integrations when possible.'
      },
      {
        id: 'SECRET-GITHUB-002',
        name: 'GitHub OAuth Access Token',
        description: 'GitHub OAuth Access Token detected.',
        severity: 'high',
        patterns: [/gho_[A-Za-z0-9]{36}/g],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Revoke the OAuth token in GitHub Settings.\n2. Implement proper OAuth flow with token refresh.'
      },

      // Generic API Keys
      {
        id: 'SECRET-API-001',
        name: 'OpenAI API Key',
        description: 'OpenAI API Key detected. This key can be used to access OpenAI services and incur charges.',
        severity: 'critical',
        patterns: [/sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g, /sk-proj-[A-Za-z0-9]{48}/g],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Rotate the key immediately at platform.openai.com/api-keys.\n2. Use environment variables or a secrets vault.\n3. Implement key rotation policies.'
      },
      {
        id: 'SECRET-API-002',
        name: 'Anthropic API Key',
        description: 'Anthropic API Key detected.',
        severity: 'critical',
        patterns: [/sk-ant-[A-Za-z0-9\-_]{100,}/g],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Rotate the key at console.anthropic.com.\n2. Use environment variables for key storage.'
      },
      {
        id: 'SECRET-API-003',
        name: 'Slack API Token',
        description: 'Slack API Token detected. This can be used to post messages and access workspace data.',
        severity: 'high',
        patterns: [/xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Revoke at api.slack.com/authentication/bot-tokens.\n2. Use Slack App manifest for deployments.'
      },
      {
        id: 'SECRET-API-004',
        name: 'Stripe API Key',
        description: 'Stripe API Key detected. This key can access payment processing.',
        severity: 'critical',
        patterns: [/sk_live_[0-9a-zA-Z]{24}/g, /sk_test_[0-9a-zA-Z]{24}/g, /rk_live_[0-9a-zA-Z]{24}/g],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Rotate immediately at dashboard.stripe.com/apikeys.\n2. Use restricted keys with limited permissions.\n3. Never use live keys in development.'
      },

      // Database Credentials
      {
        id: 'SECRET-DB-001',
        name: 'Database Connection String',
        description: 'Database connection string with credentials detected.',
        severity: 'critical',
        patterns: [/(postgres|postgresql|mysql|mongodb|redis):\/\/[^:]+:[^@]+@[^\/]+/gi],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Rotate database credentials.\n2. Use connection string without credentials, pass separately.\n3. Use IAM authentication where supported (AWS RDS, Azure SQL).'
      },
      {
        id: 'SECRET-DB-002',
        name: 'MongoDB Connection String',
        description: 'MongoDB connection string with credentials detected.',
        severity: 'critical',
        patterns: [/mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^\s]+/gi],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Rotate MongoDB credentials.\n2. Store connection string in environment variables.\n3. Use MongoDB Atlas secrets integration.'
      },

      // Auth Tokens
      {
        id: 'SECRET-AUTH-001',
        name: 'JWT Secret',
        description: 'JWT signing secret detected. This can be used to forge authentication tokens.',
        severity: 'critical',
        patterns: [/jwt[_\-]?secret["']?\s*[:=]\s*["']([A-Za-z0-9\-_]{20,})["']/gi],
        falsePositivePatterns: [/(your-secret|change-me|secret-here|example)/i],
        owasp: ['A07:2021 - Identification and Authentication Failures', 'A02:2021 - Cryptographic Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Generate a new cryptographically secure secret (at least 256 bits).\n2. Rotate all existing tokens.\n3. Store secret in environment variable or secrets manager.'
      },
      {
        id: 'SECRET-AUTH-002',
        name: 'OAuth Client Secret',
        description: 'OAuth client secret detected.',
        severity: 'high',
        patterns: [/client[_\-]?secret["']?\s*[:=]\s*["']([A-Za-z0-9\-_]{20,})["']/gi],
        falsePositivePatterns: [/(your-secret|example|change-me)/i],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Regenerate client secret in OAuth provider console.\n2. Use environment variables or secrets manager.'
      },

      // SSH Keys
      {
        id: 'SECRET-SSH-001',
        name: 'SSH Private Key',
        description: 'SSH private key detected. This can be used for unauthorized access.',
        severity: 'critical',
        patterns: [/-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Remove key from repository immediately.\n2. Generate new key pair.\n3. Rotate authorized keys on all servers.\n4. Add *.pem to .gitignore.'
      },

      // GCP Keys
      {
        id: 'SECRET-GCP-001',
        name: 'Google Cloud Service Account Key',
        description: 'GCP Service Account private key detected.',
        severity: 'critical',
        patterns: [/"private_key":\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----/g],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Delete the service account key in GCP Console.\n2. Create new key and download securely.\n3. Use Workload Identity for GKE/Cloud Run.'
      },

      // Azure Keys
      {
        id: 'SECRET-AZURE-001',
        name: 'Azure Storage Account Key',
        description: 'Azure Storage account key detected.',
        severity: 'critical',
        patterns: [/[A-Za-z0-9]{86}==/g],
        falsePositivePatterns: [/(EXAMPLE|SAMPLE)/i],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Regenerate storage account key in Azure Portal.\n2. Use Azure Key Vault for secret management.\n3. Use Managed Identities for Azure resources.'
      },

      // NPM Tokens
      {
        id: 'SECRET-NPM-001',
        name: 'NPM Access Token',
        description: 'NPM access token detected. This can be used to publish packages.',
        severity: 'high',
        patterns: [/\/\/registry\.npmjs\.org\/:_authToken=[A-Za-z0-9-]{36}/g, /npm_[A-Za-z0-9]{36}/g],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Revoke token at npmjs.com/settings/tokens.\n2. Use npmrc with environment variable substitution.'
      },

      // Private Key Patterns
      {
        id: 'SECRET-KEY-001',
        name: 'PEM Certificate',
        description: 'PEM certificate/private key detected.',
        severity: 'critical',
        patterns: [/-----BEGIN CERTIFICATE-----/g, /-----BEGIN PRIVATE KEY-----/g, /-----BEGIN ENCRYPTED PRIVATE KEY-----/g],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Remove certificate from repository.\n2. Revoke and reissue certificate.\n3. Store certificates in AWS Certificate Manager, Azure Key Vault, or similar.'
      },

      // Password in code
      {
        id: 'SECRET-PASSWORD-001',
        name: 'Hardcoded Password',
        description: 'Potential hardcoded password detected in source code.',
        severity: 'high',
        patterns: [/(?:password|passwd|pwd)["']?\s*[:=]\s*["']([^"'\s]{8,})["']/gi],
        falsePositivePatterns: [/(your_password|change_me|example|test|sample)/i],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        remediation: '1. Remove hardcoded password.\n2. Use environment variables or secrets manager.\n3. Implement proper authentication system.'
      }
    ];
  }

  private calculateEntropy(str: string): number {
    const len = str.length;
    if (len === 0) return 0;

    const freq: Record<string, number> = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  private maskSecret(secret: string): string {
    if (secret.length <= 8) {
      return '*'.repeat(secret.length);
    }
    return secret.substring(0, 4) + '*'.repeat(secret.length - 8) + secret.substring(secret.length - 4);
  }

  private calculateConfidence(match: string, pattern: SecretPattern): number {
    let confidence = 0.8;

    // Increase confidence for longer matches
    if (match.length > 30) confidence += 0.05;
    if (match.length > 50) confidence += 0.05;

    // Decrease for test indicators
    if (/(test|example|sample|demo|fake|dummy)/i.test(match)) {
      confidence -= 0.3;
    }

    // Check for placeholder patterns
    if (/(xxx|yyy|zzz|your_|my_|change_me)/i.test(match)) {
      confidence -= 0.5;
    }

    return Math.max(0, Math.min(1, confidence));
  }

  private estimateFalsePositive(match: string, pattern: SecretPattern, line: string): number {
    let likelihood = 0.1;

    // Check if in test file
    if (/(test|spec|mock|fixture|example|sample)/i.test(line)) {
      likelihood += 0.4;
    }

    // Check for comments
    if (/^\s*(\/\/|#|\/\*|\*)/.test(line)) {
      likelihood += 0.3;
    }

    // Check for documentation patterns
    if (/(readme|documentation|example\.com)/i.test(line)) {
      likelihood += 0.5;
    }

    return Math.max(0, Math.min(1, likelihood));
  }

  private isBinary(content: string): boolean {
    // Check for null bytes or high ratio of non-printable characters
    if (content.includes('\0')) return true;

    const nonPrintable = content.split('').filter(c => {
      const code = c.charCodeAt(0);
      return code < 32 && code !== 9 && code !== 10 && code !== 13;
    }).length;

    return nonPrintable / content.length > 0.1;
  }
}
