// SAST Scanner - Static Application Security Testing
import { BaseScanner } from './base.js';
import { ScanContext, ScanResult, Finding, SASTRule, Severity } from '../types.js';

export class SASTScanner extends BaseScanner {
  private rules: SASTRule[];

  constructor() {
    super();
    this.rules = this.loadSASTRules();
  }

  name(): string {
    return 'OmniGuard SAST Scanner';
  }

  type(): 'sast' {
    return 'sast';
  }

  version(): string {
    return '1.0.0';
  }

  supportedLanguages(): string[] {
    return ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust'];
  }

  supportedFiles(): string[] {
    return ['*.js', '*.ts', '*.jsx', '*.tsx', '*.py', '*.java', '*.go', '*.rb', '*.php', '*.cs', '*.rs'];
  }

  async scan(context: ScanContext): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];
    let filesScanned = 0;
    let filesSkipped = 0;

    const files = this.filterByLanguage(this.filterFiles(context), context.options.enabledScanners);

    for (const file of files) {
      if (file.size > context.options.maxFileSize) {
        filesSkipped++;
        continue;
      }

      filesScanned++;
      const language = this.detectLanguage(file.relativePath);
      const fileFindings = this.scanFile(file.relativePath, file.content, language);
      findings.push(...fileFindings);
    }

    return {
      scanner: this.type(),
      findings,
      metadata: this.createMetadata(startTime, filesScanned, filesSkipped, 0),
      summary: this.createSummary(findings)
    };
  }

  private detectLanguage(filePath: string): string {
    const ext = filePath.split('.').pop()?.toLowerCase();
    const mapping: Record<string, string> = {
      'js': 'javascript',
      'jsx': 'javascript',
      'ts': 'typescript',
      'tsx': 'typescript',
      'py': 'python',
      'java': 'java',
      'go': 'go',
      'rb': 'ruby',
      'php': 'php',
      'cs': 'csharp',
      'rs': 'rust'
    };
    return mapping[ext || ''] || 'unknown';
  }

  private scanFile(filePath: string, content: string, language: string): Finding[] {
    const findings: Finding[] = [];
    const lines = content.split('\n');

    const applicableRules = this.rules.filter(rule =>
      rule.languages.includes('*') || rule.languages.includes(language)
    );

    for (const rule of applicableRules) {
      for (const pattern of rule.patterns) {
        try {
          const regex = new RegExp(pattern.pattern, 'gm');
          let match;

          while ((match = regex.exec(content)) !== null) {
            const beforeMatch = content.substring(0, match.index);
            const lineNumber = beforeMatch.split('\n').length;
            const lineContent = lines[lineNumber - 1]?.trim() || '';

            // Skip if in comment
            if (this.isInComment(lineContent, language)) continue;

            // Skip if in string literal test
            if (this.isLikelyTest(filePath, lineContent)) continue;

            findings.push({
              id: this.generateId(),
              scanner: 'sast',
              category: rule.name,
              severity: pattern.severity || rule.severity,
              title: pattern.message || `${rule.name} detected`,
              description: rule.description,
              evidence: this.extractEvidence(match[0], content, match.index),
              file_path: filePath,
              line_start: lineNumber,
              line_end: lineNumber,
              column_start: this.getColumn(content, match.index),
              column_end: this.getColumn(content, match.index + match[0].length),
              rule_id: rule.id,
              rule_name: rule.name,
              owasp: rule.owasp,
              cwe: rule.cwe,
              mitre: rule.mitre,
              remediation: rule.remediation,
              confidence_score: 0.85,
              false_positive_likelihood: this.estimateFalsePositive(filePath, lineContent),
              metadata: {
                language,
                matched_pattern: pattern.pattern
              }
            });
          }
        } catch (e) {
          // Invalid regex, skip
        }
      }
    }

    return findings;
  }

  private loadSASTRules(): SASTRule[] {
    return [
      // SQL Injection
      {
        id: 'SAST-SQL-001',
        name: 'SQL Injection',
        description: 'Potential SQL injection vulnerability detected. User input is being concatenated into SQL queries without proper sanitization.',
        severity: 'critical',
        languages: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'csharp'],
        patterns: [
          { pattern: 'execute\\s*\\(\\s*[\'"`]\\s*SELECT.+?\\+\\s*\\w+', message: 'SQL string concatenation with variable' },
          { pattern: 'query\\s*\\(\\s*[\'"`]\\s*SELECT.+?\\+\\s*\\w+', message: 'Query with string concatenation' },
          { pattern: 'cursor\\.execute\\s*\\(\\s*f[\'"`].*?\\{.*?\\}', message: 'Python f-string SQL injection' },
          { pattern: '\\$sql\\s*=\\s*["\'].*?\\$\\w+', message: 'PHP SQL injection with variable interpolation' },
          { pattern: 'statement\\.execute\\([\'"`].*?\\+\\s*\\w+', message: 'Java SQL injection' }
        ],
        owasp: ['A03:2021 - Injection'],
        cwe: ['CWE-89'],
        mitre: ['T1190'],
        remediation: '1. Use parameterized queries/prepared statements.\n2. Use ORM query builders.\n3. Validate and sanitize all user input.\n4. Apply principle of least privilege to database accounts.'
      },

      // XSS
      {
        id: 'SAST-XSS-001',
        name: 'Cross-Site Scripting (XSS)',
        description: 'Potential XSS vulnerability. Untrusted data is being rendered to the page without proper escaping.',
        severity: 'high',
        languages: ['javascript', 'typescript'],
        patterns: [
          { pattern: 'innerHTML\\s*=\\s*[^`]*\\+', message: 'Setting innerHTML with concatenation' },
          { pattern: 'document\\.write\\s*\\(', message: 'Use of document.write with dynamic content' },
          { pattern: 'dangerouslySetInnerHTML', message: 'React dangerouslySetInnerHTML usage' },
          { pattern: '\\$\\(.*?\\)\\.html\\s*\\([^)]*\\+', message: 'jQuery .html() with concatenation' },
          { pattern: 'v-html\\s*=\\s*["\'].*?\\+', message: 'Vue v-html directive with concatenation' }
        ],
        owasp: ['A03:2021 - Injection'],
        cwe: ['CWE-79'],
        mitre: ['T1189'],
        remediation: '1. Use textContent instead of innerHTML.\n2. Use React\'s automatic JSX escaping.\n3. Sanitize HTML with DOMPurify before rendering.\n4. Implement Content Security Policy (CSP).'
      },

      // Command Injection
      {
        id: 'SAST-CMD-001',
        name: 'Command Injection',
        description: 'Potential command injection vulnerability. User input may be passed to system commands.',
        severity: 'critical',
        languages: ['javascript', 'typescript', 'python', 'php', 'ruby', 'go'],
        patterns: [
          { pattern: 'exec\\s*\\(\\s*[^`]*\\+\\s*', message: 'exec() with string concatenation' },
          { pattern: 'eval\\s*\\(\\s*[^`]*\\+\\s*', message: 'eval() with concatenation - dangerous!' },
          { pattern: 'subprocess\\.(?:call|run|Popen)\\s*\\([^)]*shell\\s*=\\s*True', message: 'Python subprocess with shell=True' },
          { pattern: 'os\\.system\\s*\\(', message: 'os.system usage' },
          { pattern: 'child_process\\.(?:exec|spawn)\\s*\\([^`]*\\+\\s*', message: 'Node.js child_process with concatenation' },
          { pattern: 'exec\\s*\\(\\s*["\'].*?\\$\\w+', message: 'PHP exec with variable interpolation' }
        ],
        owasp: ['A03:2021 - Injection'],
        cwe: ['CWE-78'],
        mitre: ['T1190'],
        remediation: '1. Avoid shell=True in subprocess calls.\n2. Use execFile with array arguments.\n3. Validate and sanitize all inputs.\n4. Use allowlists for accepted commands.'
      },

      // Path Traversal
      {
        id: 'SAST-PATH-001',
        name: 'Path Traversal',
        description: 'Potential path traversal vulnerability. User input may be used to construct file paths.',
        severity: 'high',
        languages: ['javascript', 'typescript', 'python', 'java', 'go', 'php'],
        patterns: [
          { pattern: 'path\\.join\\s*\\([^)]*req\\.', message: 'Path join with request data' },
          { pattern: 'open\\s*\\([^)]*\\+\\s*\\w+', message: 'File open with concatenation' },
          { pattern: 'fs\\.(?:readFile|writeFile)\\s*\\([^)]*\\+\\s*', message: 'fs operation with concatenation' },
          { pattern: 'new File\\([^)]*\\+\\s*', message: 'Java File with concatenation' },
          { pattern: 'ioutil\\.ReadFile\\s*\\([^)]*\\+\\s*', message: 'Go ReadFile with concatenation' }
        ],
        owasp: ['A01:2021 - Broken Access Control'],
        cwe: ['CWE-22'],
        mitre: ['T1083'],
        remediation: '1. Validate and sanitize path inputs.\n2. Use path.resolve and check against allowed directories.\n3. Implement allowlists for permitted files.\n4. Never trust user input for file paths.'
      },

      // SSRF
      {
        id: 'SAST-SSRF-001',
        name: 'Server-Side Request Forgery (SSRF)',
        description: 'Potential SSRF vulnerability. User input may be used to make server-side requests.',
        severity: 'critical',
        languages: ['javascript', 'typescript', 'python', 'java', 'go', 'php'],
        patterns: [
          { pattern: 'fetch\\s*\\([^)]*req\\.', message: 'fetch with request data' },
          { pattern: 'axios\\.\\w+\\s*\\([^)]*req\\.', message: 'axios with request data' },
          { pattern: 'requests\\.(?:get|post)\\s*\\([^)]*\\+\\s*', message: 'Python requests with concatenation' },
          { pattern: 'http\\.Get\\s*\\([^)]*\\+\\s*', message: 'Go http.Get with concatenation' },
          { pattern: 'HttpClient\\.[^)]*\\([^)]*\\+\\s*', message: 'Java HTTP client with concatenation' },
          { pattern: 'curl_exec\\s*\\(', message: 'PHP curl_exec usage with dynamic URL' }
        ],
        owasp: ['A10:2021 - Server-Side Request Forgery'],
        cwe: ['CWE-918'],
        mitre: ['T1190'],
        remediation: '1. Validate and sanitize URLs.\n2. Use allowlists for permitted domains.\n3. Block private IP ranges.\n4. Disable follow redirects.\n5. Use a dedicated HTTP client with SSRF protections.'
      },

      // Unsafe Deserialization
      {
        id: 'SAST-DESERIALIZE-001',
        name: 'Unsafe Deserialization',
        description: 'Potential unsafe deserialization. Deserializing untrusted data can lead to RCE.',
        severity: 'critical',
        languages: ['javascript', 'typescript', 'python', 'java', 'php', 'csharp'],
        patterns: [
          { pattern: 'pickle\\.loads?\\s*\\(', message: 'Python pickle usage - dangerous!' },
          { pattern: 'yaml\\.load\\s*\\([^)]*Loader\\s*=\\s*yaml\\.FullLoader', message: 'yaml.load without SafeLoader' },
          { pattern: 'ObjectInputStream', message: 'Java ObjectInputStream usage' },
          { pattern: 'unserialize\\s*\\(', message: 'PHP unserialize usage' },
          { pattern: 'JSON\\.parse\\s*\\([^)]*atob\\s*\\(', message: 'Parsing base64 JSON without validation' }
        ],
        owasp: ['A08:2021 - Software and Data Integrity Failures'],
        cwe: ['CWE-502'],
        mitre: ['T1190'],
        remediation: '1. Use JSON.parse for JSON data.\n2. Avoid pickle/yaml.load with untrusted data.\n3. Use yaml.safe_load instead.\n4. Implement schema validation before processing.'
      },

      // Weak Crypto
      {
        id: 'SAST-CRYPTO-001',
        name: 'Weak Cryptography',
        description: 'Weak or broken cryptographic algorithm detected.',
        severity: 'high',
        languages: ['javascript', 'typescript', 'python', 'java', 'php', 'go'],
        patterns: [
          { pattern: 'MD5\\s*\\(', message: 'MD5 usage - cryptographically broken' },
          { pattern: 'SHA1\\s*\\(', message: 'SHA-1 usage - cryptographically weak' },
          { pattern: 'DES\\s*\\(', message: 'DES usage - too weak' },
          { pattern: 'crypto\\.createHash\\s*\\(["\']md5["\']', message: 'Node.js MD5 usage' },
          { pattern: 'crypto\\.createHash\\s*\\(["\']sha1["\']', message: 'Node.js SHA-1 usage' },
          { pattern: 'ecb', message: 'ECB mode usage - not semantically secure' },
          { pattern: 'Math\\.random\\s*\\(\\)', message: 'Math.random used for security purposes' }
        ],
        owasp: ['A02:2021 - Cryptographic Failures'],
        cwe: ['CWE-328', 'CWE-327'],
        mitre: [],
        remediation: '1. Use SHA-256 or SHA-3 for hashing.\n2. Use AES-256-GCM for encryption.\n3. Use crypto.randomBytes for random values.\n4. For passwords, use bcrypt/scrypt/argon2.'
      },

      // Hardcoded Credentials
      {
        id: 'SAST-AUTH-001',
        name: 'Hardcoded Credentials',
        description: 'Hardcoded credentials detected in source code.',
        severity: 'critical',
        languages: ['javascript', 'typescript', 'python', 'java', 'go', 'php', 'ruby', 'csharp'],
        patterns: [
          { pattern: 'password\\s*=\\s*["\'][^"\']{8,}["\']', message: 'Hardcoded password assignment' },
          { pattern: 'api[_-]?key\\s*=\\s*["\'][^"\']{20,}["\']', message: 'Hardcoded API key' },
          { pattern: 'secret\\s*=\\s*["\'][^"\']{16,}["\']', message: 'Hardcoded secret' },
          { pattern: 'token\\s*=\\s*["\'][^"\']{20,}["\']', message: 'Hardcoded token' },
          { pattern: 'Authorization:\\s*Bearer\\s+[^"\'\\s]{20,}', message: 'Hardcoded Bearer token' }
        ],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-798'],
        mitre: [],
        remediation: '1. Use environment variables for credentials.\n2. Use secrets management service.\n3. Implement proper secret rotation.'
      },

      // JWT Issues
      {
        id: 'SAST-JWT-001',
        name: 'JWT Security Issues',
        description: 'JWT security misconfiguration detected.',
        severity: 'high',
        languages: ['javascript', 'typescript', 'python', 'java'],
        patterns: [
          { pattern: 'verify\\s*\\([^,]+,\\s*["\']none["\']', message: 'JWT with "none" algorithm - critical!' },
          { pattern: 'algorithm\\s*:\\s*["\']none["\']', message: 'JWT algorithm set to none' },
          { pattern: 'jwt\\.sign\\([^)]+\\s*,\\s*["\'][^"\']{5,20}["\']', message: 'JWT secret too short (< 32 chars)' },
          { pattern: 'expiresIn\\s*:\\s*[0-9]{8,}', message: 'Very long JWT expiry time' }
        ],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-287'],
        mitre: [],
        remediation: '1. Never use "none" algorithm.\n2. Use strong secrets (256+ bits).\n3. Set reasonable expiry times.\n4. Validate algorithm in token header.'
      },

      // CORS Misconfiguration
      {
        id: 'SAST-CORS-001',
        name: 'CORS Misconfiguration',
        description: 'Overly permissive CORS configuration detected.',
        severity: 'medium',
        languages: ['javascript', 'typescript', 'python'],
        patterns: [
          { pattern: 'Access-Control-Allow-Origin\\s*:\\s*["\']\\*["\']', message: 'CORS allows all origins' },
          { pattern: 'cors\\s*\\(\\s*\\{\\s*origin\\s*:\\s*["\']\\*["\']', message: 'Express CORS allows all origins' },
          { pattern: 'CORS_ORIGIN\\s*=\\s*["\']\\*["\']', message: 'Wildcard CORS in environment' },
          { pattern: 'credentials\\s*:\\s*true.*origin\\s*:\\s*["\']\\*["\']', message: 'Credentials with wildcard origin' }
        ],
        owasp: ['A01:2021 - Broken Access Control', 'A05:2021 - Security Misconfiguration'],
        cwe: ['CWE-942'],
        mitre: [],
        remediation: '1. Specify allowed origins explicitly.\n2. Never use wildcard with credentials.\n3. Validate origin against allowlist.'
      },

      // Insecure Dependencies
      {
        id: 'SAST-DEP-001',
        name: 'Known Vulnerable Dependency Pattern',
        description: 'Potential use of known vulnerable code patterns.',
        severity: 'high',
        languages: ['javascript', 'typescript'],
        patterns: [
          { pattern: 'lodash\\s*<\\s*4\\.17\\.21', message: 'Vulnerable lodash version (prototype pollution)' },
          { pattern: 'node-serialize', message: 'node-serialize has RCE vulnerability' },
          { pattern: 'angular\\.module[^)]*\\$parse', message: 'AngularJS expression injection risk' }
        ],
        owasp: ['A06:2021 - Vulnerable and Outdated Components'],
        cwe: ['CWE-1035'],
        mitre: [],
        remediation: '1. Update to latest stable version.\n2. Run npm audit regularly.\n3. Use Dependabot or Snyk for monitoring.'
      },

      // Improper Error Handling
      {
        id: 'SAST-ERR-001',
        name: 'Improper Error Handling',
        description: 'Error handling may expose sensitive information.',
        severity: 'medium',
        languages: ['javascript', 'typescript', 'python', 'java', 'php'],
        patterns: [
          { pattern: 'res\\.send\\(.*?err\\)', message: 'Sending error details in response' },
          { pattern: 'res\\.json\\(\\s*\\{.*?error.*?\\}\\s*\\)', message: 'JSON error response with details' },
          { pattern: 'print\\(.*?exception.*?\\)', message: 'Printing exception details' },
          { pattern: 'e\\.printStackTrace\\(\\)', message: 'Printing stack trace' }
        ],
        owasp: ['A05:2021 - Security Misconfiguration'],
        cwe: ['CWE-209'],
        mitre: [],
        remediation: '1. Log errors server-side only.\n2. Return generic error messages.\n3. Never expose stack traces to users.'
      },

      // Rate Limiting Missing
      {
        id: 'SAST-RATE-001',
        name: 'Missing Rate Limiting',
        description: 'No rate limiting detected on authentication endpoints.',
        severity: 'medium',
        languages: ['javascript', 'typescript', 'python'],
        patterns: [
          { pattern: 'app\\.post\\s*\\(["\'/login["\']', message: 'Login endpoint without rate limiting' },
          { pattern: '@app\\.route\\s*\\(["\'/login["\']', message: 'Python login route without rate limiting' },
          { pattern: 'express-rate-limit', message: 'Rate limiting may be configured (verify)' }
        ],
        owasp: ['A07:2021 - Identification and Authentication Failures'],
        cwe: ['CWE-770'],
        mitre: [],
        remediation: '1. Implement rate limiting on auth endpoints.\n2. Use express-rate-limit or similar.\n3. Implement exponential backoff.'
      },

      // Open Redirect
      {
        id: 'SAST-REDIRECT-001',
        name: 'Open Redirect',
        description: 'Potential open redirect vulnerability.',
        severity: 'medium',
        languages: ['javascript', 'typescript', 'python', 'php'],
        patterns: [
          { pattern: 'res\\.redirect\\s*\\(\\s*req\\.(?:query|body)\\.\\w+', message: 'Redirect from user input' },
          { pattern: 'header\\s*\\(\\s*["\']Location["\']\\s*,\\s*req\\.', message: 'Location header from request' },
          { pattern: 'response\\.redirect\\s*\\([^)]*\\+', message: 'Redirect with concatenation' }
        ],
        owasp: ['A01:2021 - Broken Access Control'],
        cwe: ['CWE-601'],
        mitre: ['T1204'],
        remediation: '1. Validate redirect URLs against allowlist.\n2. Use relative URLs for redirects.\n3. Never redirect to user-provided URLs.'
      }
    ];
  }

  private extractEvidence(match: string, content: string, index: number): string {
    const start = Math.max(0, index - 50);
    const end = Math.min(content.length, index + match.length + 50);
    return content.substring(start, end).replace(/\s+/g, ' ').trim();
  }

  private getColumn(content: string, index: number): number {
    const lineStart = content.lastIndexOf('\n', index - 1) + 1;
    return index - lineStart + 1;
  }

  private isInComment(line: string, language: string): boolean {
    const trimmed = line.trim();
    switch (language) {
      case 'javascript':
      case 'typescript':
      case 'java':
      case 'csharp':
      case 'go':
      case 'rust':
        return trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*');
      case 'python':
      case 'ruby':
        return trimmed.startsWith('#');
      case 'php':
        return trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('/*');
      default:
        return false;
    }
  }

  private isLikelyTest(filePath: string, line: string): boolean {
    const testPatterns = [
      /test|spec|mock|fixture/i,
      /describe\s*\(|it\s*\(|test\s*\(/,
      /expect\s*\(|assert\s*\(|should\./,
      /\.test\./i
    ];
    return testPatterns.some(p => p.test(filePath) || p.test(line));
  }

  private estimateFalsePositive(filePath: string, line: string): number {
    let likelihood = 0.1;

    if (this.isLikelyTest(filePath, line)) {
      likelihood += 0.5;
    }

    if (/(example|sample|demo|tutorial)/i.test(filePath)) {
      likelihood += 0.3;
    }

    return Math.max(0, Math.min(1, likelihood));
  }

  private filterByLanguage(files: import('../types.js').ScannedFile[], _scanners: import('../types.js').ScannerType[] | string[]): import('../types.js').ScannedFile[] {
    return files.filter(f => {
      const lang = this.detectLanguage(f.relativePath);
      return this.supportedLanguages().includes(lang);
    });
  }
}
