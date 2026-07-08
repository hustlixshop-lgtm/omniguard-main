// OmniGuard Security Scanner - Main Entry Point
import { SecretScanner } from './scanners/secret-scanner.js';
import { SASTScanner } from './scanners/sast-scanner.js';
import { IaCScanner } from './scanners/iac-scanner.js';
import { DependencyScanner } from './scanners/dependency-scanner.js';
import { ClaudeAIProvider } from './ai/provider.js';
import {
  Scanner,
  ScanContext,
  ScanResult,
  Finding,
  ScanOptions,
  ScannerType,
  ScannedFile,
  AIAnalysisResult,
  Severity
} from './types.js';
import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import ignore from 'ignore';
import * as crypto from 'crypto';

export { SecretScanner, SASTScanner, IaCScanner, DependencyScanner };
export { ClaudeAIProvider } from './ai/provider.js';
export * from './types.js';

export interface FullScanResult {
  findings: Finding[];
  summaries: Record<ScannerType, ScanResult['summary']>;
  metadata: {
    total_files: number;
    files_scanned: number;
    duration_ms: number;
    scanners_run: ScannerType[];
  };
  aiAnalysis?: AIAnalysisResult;
}

export class OmniGuardScanner {
  private scanners: Map<ScannerType, Scanner>;
  private aiProvider: ClaudeAIProvider;
  private defaultOptions: ScanOptions;

  constructor(options?: Partial<ScanOptions>) {
    this.scanners = new Map();
    this.scanners.set('secret', new SecretScanner());
    this.scanners.set('sast', new SASTScanner());
    this.scanners.set('iac', new IaCScanner());
    this.scanners.set('dependency', new DependencyScanner());

    this.aiProvider = new ClaudeAIProvider();

    this.defaultOptions = {
      enabledScanners: ['secret', 'sast', 'iac', 'dependency'],
      excludePatterns: [
        'node_modules/**',
        '.git/**',
        'dist/**',
        'build/**',
        '**/*.min.js',
        '**/*.map',
        'vendor/**',
        '.venv/**',
        'venv/**',
        '__pycache__/**',
        'coverage/**',
        '.next/**'
      ],
      includePatterns: [],
      failOn: 'high',
      maxFileSize: 1024 * 1024, // 1MB
      timeout: 300000, // 5 minutes
      aiEnabled: true,
      aiModel: 'haiku',
      ...options
    };
  }

  setApiKey(key: string): void {
    this.aiProvider.setApiKey(key);
  }

  async scanRepository(repoPath: string, options?: Partial<ScanOptions>): Promise<FullScanResult> {
    const startTime = Date.now();
    const mergedOptions = { ...this.defaultOptions, ...options };

    // Get all files
    const files = await this.getRepositoryFiles(repoPath, mergedOptions);
    const allFindings: Finding[] = [];
    const summaries: Record<ScannerType, ScanResult['summary']> = {} as Record<ScannerType, ScanResult['summary']>;

    // Run each scanner
    const scannersToRun = mergedOptions.enabledScanners;

    for (const scannerType of scannersToRun) {
      const scanner = this.scanners.get(scannerType);
      if (!scanner) continue;

      const context: ScanContext = {
        repositoryPath: repoPath,
        basePath: repoPath,
        files,
        options: mergedOptions
      };

      const result = await scanner.scan(context);
      allFindings.push(...result.findings);
      summaries[scannerType] = result.summary;
    }

    // Run AI classification if enabled
    let aiAnalysis: AIAnalysisResult | undefined;
    if (mergedOptions.aiEnabled && this.aiProvider && allFindings.length > 0) {
      const criticalAndHigh = allFindings.filter(f => f.severity === 'critical' || f.severity === 'high');

      if (criticalAndHigh.length > 0) {
        aiAnalysis = await this.aiProvider.classify({
          type: 'classify',
          context: { repositoryPath: repoPath, basePath: repoPath, files: files.slice(0, 100), options: mergedOptions },
          findings: criticalAndHigh.slice(0, 20)
        });

        // For critical findings, get detailed remediation
        for (const finding of allFindings.filter(f => f.severity === 'critical').slice(0, 5)) {
          const file = files.find(f => f.relativePath === finding.file_path);
          if (file && file.content.length < 50000) {
            const remediation = await this.aiProvider.remediate({
              type: 'remediate',
              context: { repositoryPath: repoPath, basePath: repoPath, files: [file], options: mergedOptions },
              findings: [finding],
              file
            });

            if (remediation.remediation) {
              finding.remediation = remediation.remediation;
              finding.evidence = remediation.reasoning;
            }
          }
        }
      }
    }

    const duration = Date.now() - startTime;

    return {
      findings: allFindings.sort((a, b) => {
        const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
        return severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
      }),
      summaries,
      metadata: {
        total_files: files.length,
        files_scanned: files.length,
        duration_ms: duration,
        scanners_run: scannersToRun
      },
      aiAnalysis
    };
  }

  async scanFile(filePath: string, content?: string): Promise<FullScanResult> {
    const absolutePath = path.resolve(filePath);
    const fileContent = content || fs.readFileSync(absolutePath, 'utf-8');
    const relativePath = path.basename(absolutePath);

    const scannedFile: ScannedFile = {
      path: absolutePath,
      relativePath,
      content: fileContent,
      size: fileContent.length,
      language: this.detectLanguage(absolutePath),
      hash: this.hashContent(fileContent)
    };

    const context: ScanContext = {
      repositoryPath: path.dirname(absolutePath),
      basePath: path.dirname(absolutePath),
      files: [scannedFile],
      options: this.defaultOptions
    };

    const allFindings: Finding[] = [];
    const summaries: Record<ScannerType, ScanResult['summary']> = {} as Record<ScannerType, ScanResult['summary']>;

    for (const scannerType of ['secret', 'sast', 'iac'] as ScannerType[]) {
      const scanner = this.scanners.get(scannerType);
      if (!scanner) continue;

      const result = await scanner.scan(context);
      allFindings.push(...result.findings);
      summaries[scannerType] = result.summary;
    }

    // AI classification for the file
    let aiAnalysis: AIAnalysisResult | undefined;
    if (this.defaultOptions.aiEnabled && this.aiProvider) {
      aiAnalysis = await this.aiProvider.analyzeFile(scannedFile, 'haiku');
    }

    return {
      findings: allFindings,
      summaries,
      metadata: {
        total_files: 1,
        files_scanned: 1,
        duration_ms: 0,
        scanners_run: ['secret', 'sast', 'iac']
      },
      aiAnalysis
    };
  }

  async quickClassify(filePath: string, content: string): Promise<'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'> {
    const result = await this.scanFile(filePath, content);

    const hasCritical = result.findings.some(f => f.severity === 'critical');
    const hasHigh = result.findings.some(f => f.severity === 'high');
    const hasMedium = result.findings.some(f => f.severity === 'medium');

    if (hasCritical) return 'CRITICAL';
    if (hasHigh) return 'HIGH';
    if (hasMedium) return 'MEDIUM';

    if (result.findings.length > 0) {
      return 'LOW';
    }

    if (result.aiAnalysis?.classification) {
      return result.aiAnalysis.classification;
    }

    return 'SAFE';
  }

  private async getRepositoryFiles(repoPath: string, options: ScanOptions): Promise<ScannedFile[]> {
    const ig = ignore().add(options.excludePatterns);

    // Try to load .gitignore
    const gitignorePath = path.join(repoPath, '.gitignore');
    if (fs.existsSync(gitignorePath)) {
      const gitignore = fs.readFileSync(gitignorePath, 'utf-8');
      ig.add(gitignore.split('\n').filter(line => line.trim() && !line.startsWith('#')));
    }

    const files: ScannedFile[] = [];
    const patterns = options.includePatterns.length > 0 ? options.includePatterns : ['**/*'];

    for (const pattern of patterns) {
      const matches = await glob(pattern, {
        cwd: repoPath,
        absolute: true,
        nodir: true,
        ignore: options.excludePatterns
      });

      for (const filePath of matches) {
        const relativePath = path.relative(repoPath, filePath);

        if (ig.ignores(relativePath)) continue;

        try {
          const stat = fs.statSync(filePath);
          if (stat.size > options.maxFileSize) continue;

          const content = fs.readFileSync(filePath, 'utf-8');

          files.push({
            path: filePath,
            relativePath,
            content,
            size: stat.size,
            language: this.detectLanguage(filePath),
            hash: this.hashContent(content)
          });
        } catch {
          // Skip files we can't read
        }
      }
    }

    return files;
  }

  private detectLanguage(filePath: string): string {
    const ext = path.extname(filePath).toLowerCase();
    const mapping: Record<string, string> = {
      '.js': 'javascript',
      '.jsx': 'javascript',
      '.ts': 'typescript',
      '.tsx': 'typescript',
      '.py': 'python',
      '.java': 'java',
      '.go': 'go',
      '.rb': 'ruby',
      '.php': 'php',
      '.cs': 'csharp',
      '.rs': 'rust',
      '.c': 'c',
      '.cpp': 'cpp',
      '.h': 'c',
      '.hpp': 'cpp',
      '.swift': 'swift',
      '.kt': 'kotlin',
      '.scala': 'scala',
      '.tf': 'terraform',
      '.hcl': 'hcl',
      '.yaml': 'yaml',
      '.yml': 'yaml',
      '.json': 'json',
      '.xml': 'xml',
      '.html': 'html',
      '.css': 'css',
      '.scss': 'scss',
      '.sh': 'bash',
      '.dockerfile': 'dockerfile'
    };
    return mapping[ext] || 'unknown';
  }

  private hashContent(content: string): string {
    return crypto.createHash('sha256').update(content).digest('hex').substring(0, 16);
  }
}

// Default export
export default OmniGuardScanner;

// CLI entry point
if (import.meta.url === `file://${process.argv[1]}`) {
  const scanner = new OmniGuardScanner();
  const repoPath = process.argv[2] || process.cwd();

  console.log(`\n🔒 OmniGuard Security Scanner\n`);
  console.log(`Scanning: ${repoPath}\n`);

  scanner.scanRepository(repoPath).then(result => {
    console.log(`\n📊 Scan Results:\n`);
    console.log(`Files scanned: ${result.metadata.total_files}`);
    console.log(`Duration: ${result.metadata.duration_ms}ms`);
    console.log(`\nFindings by severity:`);
    console.log(`  🔴 Critical: ${result.findings.filter(f => f.severity === 'critical').length}`);
    console.log(`  🟠 High: ${result.findings.filter(f => f.severity === 'high').length}`);
    console.log(`  🟡 Medium: ${result.findings.filter(f => f.severity === 'medium').length}`);
    console.log(`  🔵 Low: ${result.findings.filter(f => f.severity === 'low').length}`);
    console.log(`  ⚪ Info: ${result.findings.filter(f => f.severity === 'info').length}`);

    if (result.findings.length > 0) {
      console.log(`\n📋 Top Findings:\n`);
      for (const finding of result.findings.slice(0, 10)) {
        console.log(`[${finding.severity.toUpperCase()}] ${finding.title}`);
        console.log(`  📁 ${finding.file_path}:${finding.line_start || 1}`);
        console.log(`  📝 ${finding.rule_name}`);
        console.log(``);
      }
    }

    if (result.aiAnalysis) {
      console.log(`\n🤖 AI Analysis:`);
      console.log(`Classification: ${result.aiAnalysis.classification}`);
      console.log(`Confidence: ${(result.aiAnalysis.confidence * 100).toFixed(0)}%`);
      console.log(`Reasoning: ${result.aiAnalysis.reasoning}`);
    }

    process.exit(result.findings.some(f => f.severity === 'critical' || f.severity === 'high') ? 1 : 0);
  }).catch(err => {
    console.error('Scan failed:', err.message);
    process.exit(2);
  });
}
