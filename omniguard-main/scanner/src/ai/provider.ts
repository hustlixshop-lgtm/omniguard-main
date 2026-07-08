// AI Provider Abstraction - Anthropic Claude Integration
import Anthropic from '@anthropic-ai/sdk';
import { AIProvider, AIAnalysisRequest, AIAnalysisResult, Finding, ScannedFile } from '../types.js';

const HAIKU_MODEL = 'claude-3-5-haiku-20241022';
const SONNET_MODEL = 'claude-3-5-sonnet-20241022';
const OPUS_MODEL = 'claude-3-opus-20240229';

export class ClaudeAIProvider implements AIProvider {
  private client: Anthropic | null = null;
  private apiKey: string | null = null;
  private defaultModel: 'haiku' | 'sonnet' | 'opus' = 'haiku';

  constructor() {
    // Initialize from environment
    this.apiKey = process.env.ANTHROPIC_API_KEY || null;
    if (this.apiKey) {
      this.client = new Anthropic({ apiKey: this.apiKey });
    }
  }

  name(): string {
    return 'Anthropic Claude';
  }

  setApiKey(key: string): void {
    this.apiKey = key;
    this.client = new Anthropic({ apiKey: key });
  }

  setModel(model: 'haiku' | 'sonnet' | 'opus'): void {
    this.defaultModel = model;
  }

  private selectModel(model: 'haiku' | 'sonnet' | 'opus' | undefined): string {
    switch (model || this.defaultModel) {
      case 'haiku': return HAIKU_MODEL;
      case 'sonnet': return SONNET_MODEL;
      case 'opus': return OPUS_MODEL;
    }
  }

  private formatContext(request: AIAnalysisRequest): string {
    const parts: string[] = [];

    if (request.file) {
      parts.push(`File: ${request.file.relativePath}`);
      parts.push(`Language: ${request.file.language || 'unknown'}`);
      parts.push(`\nContent:\n${request.file.content.substring(0, 10000)}`);
    }

    if (request.findings.length > 0) {
      parts.push(`\nFindings (${request.findings.length}):`);
      for (const f of request.findings.slice(0, 10)) {
        parts.push(`- [${f.severity.toUpperCase()}] ${f.title} (${f.file_path}:${f.line_start})`);
      }
    }

    return parts.join('\n');
  }

  async classify(request: AIAnalysisRequest): Promise<AIAnalysisResult> {
    if (!this.client) {
      return { confidence: 0, reasoning: 'AI provider not configured' };
    }

    const model = this.selectModel('haiku');

    try {
      const message = await this.client.messages.create({
        model,
        max_tokens: 1024,
        messages: [{
          role: 'user',
          content: `You are a security code classifier. Analyze the following code and classify its security risk.

File context:
${this.formatContext(request)}

Classify the security risk as one of: SAFE, LOW, MEDIUM, HIGH, CRITICAL.

Respond in JSON format:
{
  "classification": "SAFE|LOW|MEDIUM|HIGH|CRITICAL",
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation of the classification",
  "concerns": ["list of specific security concerns if any"]
}

Only respond with the JSON object, no other text.`
        }]
      });

      const text = message.content[0].type === 'text' ? message.content[0].text : '';
      const json = this.parseJSON(text);

      return {
        classification: json.classification || 'LOW',
        confidence: json.confidence || 0.5,
        reasoning: json.reasoning || 'Unable to analyze',
        references: json.concerns || []
      };
    } catch (error) {
      return {
        confidence: 0,
        reasoning: `AI classification failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  async explain(request: AIAnalysisRequest): Promise<AIAnalysisResult> {
    if (!this.client) {
      return { confidence: 0, reasoning: 'AI provider not configured' };
    }

    const model = this.selectModel('sonnet');

    const findingsContext = request.findings.map(f =>
      `[${f.severity.toUpperCase()}] ${f.title}\nFile: ${f.file_path}:${f.line_start}\nDescription: ${f.description}\nEvidence: ${f.evidence}`
    ).join('\n\n');

    try {
      const message = await this.client.messages.create({
        model,
        max_tokens: 2048,
        messages: [{
          role: 'user',
          content: `You are a security expert. Explain the following security findings in detail.

${findingsContext}

For each finding, provide:
1. Why this is a security issue
2. How it could be exploited
3. The relevant security standards (OWASP, CWE, etc.)
4. A severity assessment

Respond in JSON format:
{
  "findings": [
    {
      "id": "finding-id-or-title",
      "explanation": "Detailed explanation",
      "exploitation_scenario": "How an attacker might exploit this",
      "standards_references": ["OWASP-A01", "CWE-89", etc.],
      "severity_justification": "Why this severity is appropriate"
    }
  ],
  "overall_assessment": "Summary of the security posture",
  "confidence": 0.0-1.0
}

Only respond with the JSON object.`
        }]
      });

      const text = message.content[0].type === 'text' ? message.content[0].text : '';
      const json = this.parseJSON(text);

      return {
        confidence: json.confidence || 0.8,
        reasoning: json.overall_assessment || '',
        explanation: JSON.stringify(json.findings, null, 2),
        references: json.findings?.flatMap((f: { standards_references?: string[] }) => f.standards_references || []) || []
      };
    } catch (error) {
      return {
        confidence: 0,
        reasoning: `AI explanation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  async remediate(request: AIAnalysisRequest): Promise<AIAnalysisResult> {
    if (!this.client) {
      return { confidence: 0, reasoning: 'AI provider not configured' };
    }

    const model = this.selectModel('sonnet');

    const primaryFinding = request.findings[0];
    if (!primaryFinding) {
      return { confidence: 0, reasoning: 'No findings to remediate' };
    }

    const fileContent = request.file?.content?.substring(
      Math.max(0, (primaryFinding.line_start || 1) - 20) * 100,
      ((primaryFinding.line_end || primaryFinding.line_start || 1) + 20) * 100
    ) || '';

    try {
      const message = await this.client.messages.create({
        model,
        max_tokens: 4096,
        messages: [{
          role: 'user',
          content: `You are a secure code expert. Provide remediation for the following security vulnerability.

Vulnerability:
- Title: ${primaryFinding.title}
- Severity: ${primaryFinding.severity}
- Description: ${primaryFinding.description}
- File: ${primaryFinding.file_path}:${primaryFinding.line_start}
- Evidence: ${primaryFinding.evidence}
- Current Rule: ${primaryFinding.rule_name}

Code context:
\`\`\`
${fileContent}
\`\`\`

Provide remediation in JSON format:
{
  "remediation_steps": ["Step 1", "Step 2", ...],
  "fixed_code": "The corrected code snippet",
  "explanation": "Why this fix addresses the vulnerability",
  "additional_recommendations": ["Other security improvements"],
  "references": ["OWASP, CWE, or other references"],
  "testing_suggestions": "How to verify the fix",
  "confidence": 0.0-1.0
}

Only respond with the JSON object. Be specific with code fixes. Include the complete corrected code block.`
        }]
      });

      const text = message.content[0].type === 'text' ? message.content[0].text : '';
      const json = this.parseJSON(text);

      return {
        confidence: json.confidence || 0.85,
        reasoning: json.explanation || '',
        remediation: json.fixed_code || '',
        references: json.references || []
      };
    } catch (error) {
      return {
        confidence: 0,
        reasoning: `AI remediation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  async summarize(request: AIAnalysisRequest): Promise<AIAnalysisResult> {
    if (!this.client) {
      return { confidence: 0, reasoning: 'AI provider not configured' };
    }

    const model = this.selectModel('opus');
    const severeFindings = request.findings.filter(f => f.severity === 'critical' || f.severity === 'high');

    try {
      const message = await this.client.messages.create({
        model,
        max_tokens: 4096,
        messages: [{
          role: 'user',
          content: `You are a CISO providing an executive summary of security findings.

Total findings: ${request.findings.length}
Critical: ${request.findings.filter(f => f.severity === 'critical').length}
High: ${request.findings.filter(f => f.severity === 'high').length}
Medium: ${request.findings.filter(f => f.severity === 'medium').length}
Low: ${request.findings.filter(f => f.severity === 'low').length}

Critical and High findings:
${severeFindings.map(f => `- [${f.severity.toUpperCase()}] ${f.title} (${f.file_path})`).join('\n')}

Provide an executive summary in JSON format:
{
  "executive_summary": "2-3 sentence overview for leadership",
  "risk_assessment": "Overall risk level and justification",
  "key_vulnerabilities": ["Top 3-5 issues requiring immediate attention"],
  "recommended_actions": ["Prioritized list of remediation steps"],
  "compliance_impact": ["SOC2, HIPAA, PCI DSS impact if applicable"],
  "timeline_estimate": "Estimated effort to remediate",
  "confidence": 0.0-1.0
}

Only respond with the JSON object.`
        }]
      });

      const text = message.content[0].type === 'text' ? message.content[0].text : '';
      const json = this.parseJSON(text);

      return {
        confidence: json.confidence || 0.9,
        reasoning: json.executive_summary || '',
        explanation: JSON.stringify({
          risk_assessment: json.risk_assessment,
          key_vulnerabilities: json.key_vulnerabilities,
          recommended_actions: json.recommended_actions,
          compliance_impact: json.compliance_impact,
          timeline_estimate: json.timeline_estimate
        }, null, 2),
        references: json.compliance_impact || []
      };
    } catch (error) {
      return {
        confidence: 0,
        reasoning: `AI summary failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  async analyzeFile(file: ScannedFile, model: 'haiku' | 'sonnet' = 'haiku'): Promise<AIAnalysisResult> {
    if (!this.client) {
      return { confidence: 0, reasoning: 'AI provider not configured' };
    }

    const selectedModel = this.selectModel(model);

    try {
      const message = await this.client.messages.create({
        model: selectedModel,
        max_tokens: 2048,
        messages: [{
          role: 'user',
          content: `You are a security code analyzer. Analyze this file for security issues.

File: ${file.relativePath}
Language: ${file.language || 'unknown'}

Content:
\`\`\`
${file.content.substring(0, 15000)}
\`\`\`

Analyze for:
1. Hardcoded secrets/credentials
2. Injection vulnerabilities (SQL, XSS, command injection)
3. Insecure configurations
4. Weak cryptography
5. Authentication/authorization flaws
6. Data validation issues

Respond in JSON format:
{
  "classification": "SAFE|LOW|MEDIUM|HIGH|CRITICAL",
  "confidence": 0.0-1.0,
  "issues": [
    {
      "severity": "critical|high|medium|low|info",
      "title": "Issue title",
      "description": "What's wrong",
      "line": 123,
      "remediation": "How to fix it"
    }
  ],
  "overall_assessment": "Brief security posture summary"
}

Only respond with the JSON object.`
        }]
      });

      const text = message.content[0].type === 'text' ? message.content[0].text : '';
      const json = this.parseJSON(text);

      return {
        classification: json.classification || 'LOW',
        confidence: json.confidence || 0.5,
        reasoning: json.overall_assessment || '',
        explanation: JSON.stringify(json.issues, null, 2),
        references: []
      };
    } catch (error) {
      return {
        confidence: 0,
        reasoning: `AI analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  private parseJSON(text: string): Record<string, unknown> {
    try {
      // Try direct parse
      return JSON.parse(text);
    } catch {
      // Try to extract JSON from markdown code blocks
      const jsonMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/);
      if (jsonMatch) {
        try {
          return JSON.parse(jsonMatch[1].trim());
        } catch {
          // Fall through
        }
      }
      // Try to find any JSON object in the text
      const objectMatch = text.match(/\{[\s\S]*\}/);
      if (objectMatch) {
        try {
          return JSON.parse(objectMatch[0]);
        } catch {
          // Fall through
        }
      }
      return {};
    }
  }
}

// OpenAI Provider — real implementation
export class OpenAIProvider implements AIProvider {
  private apiKey: string | null = null;
  private model = 'gpt-4o-mini';

  constructor() {
    this.apiKey = process.env.OPENAI_API_KEY || null;
  }

  name(): string { return 'OpenAI'; }

  setApiKey(key: string): void { this.apiKey = key; }

  setModel(model: string): void { this.model = model; }

  private async call(prompt: string, maxTokens = 2048): Promise<string> {
    if (!this.apiKey) throw new Error('OpenAI API key not configured');
    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this.apiKey}` },
      body: JSON.stringify({ model: this.model, max_tokens: maxTokens, messages: [{ role: 'user', content: prompt }] }),
    });
    if (!res.ok) throw new Error(`OpenAI ${res.status}`);
    const d = await res.json() as { choices: Array<{ message: { content: string } }> };
    return d.choices?.[0]?.message?.content ?? '';
  }

  async classify(request: AIAnalysisRequest): Promise<AIAnalysisResult> {
    if (!this.apiKey) return { confidence: 0, reasoning: 'OpenAI API key not configured' };
    try {
      const text = await this.call(`Classify the security risk of this code as SAFE/LOW/MEDIUM/HIGH/CRITICAL. Return JSON: {"classification":"HIGH","confidence":0.9,"reasoning":"...","concerns":[]}\n\n${this.formatCtx(request)}`, 512);
      const json = this.parse(text);
      return { classification: json.classification as string || 'LOW', confidence: (json.confidence as number) || 0.5, reasoning: json.reasoning as string || '', references: (json.concerns as string[]) || [] };
    } catch (e) { return { confidence: 0, reasoning: String(e) }; }
  }

  async explain(request: AIAnalysisRequest): Promise<AIAnalysisResult> {
    if (!this.apiKey) return { confidence: 0, reasoning: 'OpenAI API key not configured' };
    try {
      const findings = request.findings.slice(0, 5).map(f => `[${f.severity}] ${f.title}: ${f.description}`).join('\n');
      const text = await this.call(`Explain these security findings. Return JSON: {"explanation":"...","confidence":0.8}\n\n${findings}`, 1024);
      const json = this.parse(text);
      return { confidence: (json.confidence as number) || 0.8, reasoning: '', explanation: json.explanation as string || '' };
    } catch (e) { return { confidence: 0, reasoning: String(e) }; }
  }

  async remediate(request: AIAnalysisRequest): Promise<AIAnalysisResult> {
    if (!this.apiKey) return { confidence: 0, reasoning: 'OpenAI API key not configured' };
    const f = request.findings[0];
    if (!f) return { confidence: 0, reasoning: 'No findings' };
    try {
      const text = await this.call(`Fix this vulnerability: ${f.title} at ${f.file_path}:${f.line_start}\nEvidence: ${f.evidence}\nReturn JSON: {"remediation":"fixed code","explanation":"why","confidence":0.85}`, 2048);
      const json = this.parse(text);
      return { confidence: (json.confidence as number) || 0.85, reasoning: json.explanation as string || '', remediation: json.remediation as string || '' };
    } catch (e) { return { confidence: 0, reasoning: String(e) }; }
  }

  async summarize(request: AIAnalysisRequest): Promise<AIAnalysisResult> {
    if (!this.apiKey) return { confidence: 0, reasoning: 'OpenAI API key not configured' };
    try {
      const counts = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const f of request.findings) if (f.severity in counts) counts[f.severity as keyof typeof counts]++;
      const text = await this.call(`Summarize security posture: ${JSON.stringify(counts)} findings. Return JSON: {"executive_summary":"...","risk_assessment":"HIGH","key_vulnerabilities":[],"confidence":0.9}`, 1024);
      const json = this.parse(text);
      return { confidence: (json.confidence as number) || 0.9, reasoning: json.executive_summary as string || '' };
    } catch (e) { return { confidence: 0, reasoning: String(e) }; }
  }

  private formatCtx(r: AIAnalysisRequest): string {
    const parts: string[] = [];
    if (r.file) parts.push(`File: ${r.file.relativePath}\n${r.file.content.slice(0, 5000)}`);
    if (r.findings.length) parts.push(`Findings: ${r.findings.slice(0,5).map(f => f.title).join(', ')}`);
    return parts.join('\n');
  }

  private parse(text: string): Record<string, unknown> {
    try { return JSON.parse(text); } catch {
      const m = text.match(/\{[\s\S]*\}/);
      try { return m ? JSON.parse(m[0]) : {}; } catch { return {}; }
    }
  }
}

// Provider factory
export function createAIProvider(provider: 'claude' | 'openai' = 'claude'): AIProvider {
  switch (provider) {
    case 'claude':
      return new ClaudeAIProvider();
    case 'openai':
      return new OpenAIProvider();
    default:
      return new ClaudeAIProvider();
  }
}
