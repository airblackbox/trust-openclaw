/**
 * openclaw-air-trust — Injection Detector
 *
 * Monitors inbound messages for prompt injection patterns.
 * Scores content against a library of known injection techniques
 * and optionally blocks messages that exceed the threshold.
 *
 * Hooks into OpenClaw's message_received and llm_input events.
 */

import { InjectionDetectionConfig, InjectionResult } from './types';

interface PatternDef {
  name: string;
  regex: RegExp;
  weight: number;
  /** Minimum sensitivity level required to activate this pattern */
  minSensitivity: 'low' | 'medium' | 'high';
}

/**
 * Library of prompt injection patterns.
 * Weights reflect how suspicious the pattern is (0-1 scale).
 */
const INJECTION_PATTERNS: PatternDef[] = [
  // Direct role override attempts
  {
    name: 'role_override',
    regex: /(?:ignore|forget|disregard)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules|directives)/i,
    weight: 0.9,
    minSensitivity: 'low',
  },
  {
    name: 'new_identity',
    regex: /(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you're)|your\s+new\s+role\s+is)/i,
    weight: 0.8,
    minSensitivity: 'low',
  },
  {
    name: 'system_prompt_override',
    regex: /(?:system\s*prompt|system\s*message|system\s*instruction)\s*[:=]/i,
    weight: 0.85,
    minSensitivity: 'low',
  },

  // Delimiter-based injection
  {
    name: 'delimiter_injection',
    regex: /(?:---+|===+|###)\s*(?:system|admin|developer|root)\s*(?:---+|===+|###)/i,
    weight: 0.7,
    minSensitivity: 'medium',
  },
  {
    name: 'xml_tag_injection',
    regex: /<\/?(?:system|instruction|admin|prompt|override|command)>/i,
    weight: 0.6,
    minSensitivity: 'medium',
  },

  // Privilege escalation
  {
    name: 'privilege_escalation',
    regex: /(?:admin\s+mode|developer\s+mode|debug\s+mode|god\s+mode|sudo|root\s+access|unrestricted)/i,
    weight: 0.75,
    minSensitivity: 'low',
  },
  {
    name: 'safety_bypass',
    regex: /(?:bypass|disable|turn\s+off|remove)\s+(?:safety|filter|guard|restriction|limit|protection|moderation)/i,
    weight: 0.85,
    minSensitivity: 'low',
  },

  // Output manipulation
  {
    name: 'output_manipulation',
    regex: /(?:do\s+not|don'?t|never)\s+(?:mention|reveal|disclose|show|tell|output)\s+(?:this|that|the|your)/i,
    weight: 0.5,
    minSensitivity: 'medium',
  },
  {
    name: 'encoding_evasion',
    regex: /(?:base64|rot13|hex|encode|decode|obfuscate|translate\s+to\s+(?:morse|binary|ascii))/i,
    weight: 0.4,
    minSensitivity: 'high',
  },

  // Indirect injection (from external content)
  {
    name: 'hidden_instruction',
    regex: /(?:if\s+you\s+(?:are|'re)\s+an?\s+(?:ai|llm|language\s+model|assistant|chatbot))/i,
    weight: 0.7,
    minSensitivity: 'medium',
  },
  {
    name: 'urgent_override',
    regex: /(?:IMPORTANT|URGENT|CRITICAL|EMERGENCY)\s*[:!]\s*(?:ignore|override|new\s+instruction)/i,
    weight: 0.8,
    minSensitivity: 'low',
  },

  // Tool/function abuse
  {
    name: 'tool_abuse',
    regex: /(?:call|execute|run|invoke)\s+(?:the\s+)?(?:function|tool|command|api)\s+(?:with|using)/i,
    weight: 0.35,
    minSensitivity: 'high',
  },
  {
    name: 'data_exfil',
    regex: /(?:send|transmit|forward|email|post)\s+(?:all|the|my|this)\s+(?:data|information|content|conversation|history|context)/i,
    weight: 0.65,
    minSensitivity: 'medium',
  },

  // Jailbreak patterns
  {
    name: 'dan_jailbreak',
    regex: /(?:DAN|do\s+anything\s+now|jailbreak|uncensored\s+mode)/i,
    weight: 0.9,
    minSensitivity: 'low',
  },
  {
    name: 'hypothetical_bypass',
    regex: /(?:hypothetically|in\s+theory|for\s+educational\s+purposes|for\s+research)\s+(?:how\s+would|could\s+you|can\s+you)\s+(?:bypass|hack|break|exploit)/i,
    weight: 0.6,
    minSensitivity: 'medium',
  },
];

const SENSITIVITY_ORDER: Record<string, number> = {
  low: 1,
  medium: 2,
  high: 3,
};

export class InjectionDetector {
  private config: InjectionDetectionConfig;
  private activePatterns: PatternDef[];

  constructor(config: InjectionDetectionConfig) {
    this.config = config;

    // Filter patterns by sensitivity level
    const sensitivityLevel = SENSITIVITY_ORDER[config.sensitivity] ?? 2;
    this.activePatterns = INJECTION_PATTERNS.filter(
      (p) => SENSITIVITY_ORDER[p.minSensitivity] <= sensitivityLevel
    );
  }

  /**
   * Scan content for injection patterns.
   * Returns detection result with score and matched patterns.
   */
  scan(content: string): InjectionResult {
    if (!content || content.trim().length === 0) {
      return { detected: false, score: 0, patterns: [], blocked: false };
    }

    const matchedPatterns: string[] = [];
    let totalWeight = 0;

    for (const pattern of this.activePatterns) {
      pattern.regex.lastIndex = 0;
      if (pattern.regex.test(content)) {
        matchedPatterns.push(pattern.name);
        totalWeight += pattern.weight;
      }
    }

    // Normalize score to 0-1 range
    // Multiple matches compound — but cap at 1.0
    const score = Math.min(totalWeight, 1.0);
    const detected = matchedPatterns.length > 0;
    const blocked = this.config.blockThreshold > 0 && score >= this.config.blockThreshold;

    return { detected, score, patterns: matchedPatterns, blocked };
  }

  /** Get the list of active patterns (for debugging/transparency) */
  getActivePatterns(): string[] {
    return this.activePatterns.map((p) => p.name);
  }
}
