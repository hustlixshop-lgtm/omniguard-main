// Base Scanner Abstract Class
import { Scanner, ScannerMetadata, ScanContext, ScanResult, ScanMetadata, ScanSummary, Finding } from '../types.js';
import * as crypto from 'crypto';

export abstract class BaseScanner implements Scanner {
  abstract name(): string;
  abstract type(): import('../types.js').ScannerType;
  abstract version(): string;
  abstract supportedLanguages(): string[];
  abstract supportedFiles(): string[];
  abstract scan(context: ScanContext): Promise<ScanResult>;

  metadata(): ScannerMetadata {
    return {
      name: this.name(),
      version: this.version(),
      type: this.type(),
      languages: this.supportedLanguages(),
      filePatterns: this.supportedFiles(),
      description: `${this.name()} v${this.version()} - ${this.type()} scanner`
    };
  }

  protected generateId(): string {
    return crypto.randomUUID();
  }

  protected createSummary(findings: Finding[]): ScanSummary {
    return {
      total: findings.length,
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      info: findings.filter(f => f.severity === 'info').length
    };
  }

  protected createMetadata(startTime: number, filesScanned: number, filesSkipped: number, filesErrored: number): ScanMetadata {
    return {
      files_scanned: filesScanned,
      files_skipped: filesSkipped,
      files_errored: filesErrored,
      duration_ms: Date.now() - startTime,
      scanner_version: this.version()
    };
  }

  protected filterFiles(context: ScanContext): import('../types.js').ScannedFile[] {
    const patterns = this.supportedFiles();
    if (patterns.length === 0) return context.files;

    return context.files.filter(file => {
      const path = file.relativePath.toLowerCase();
      return patterns.some(pattern => this.matchPattern(path, pattern));
    });
  }

  protected matchPattern(path: string, pattern: string): boolean {
    const regex = new RegExp('^' + pattern.replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i');
    return regex.test(path);
  }
}
