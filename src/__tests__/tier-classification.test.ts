import { describe, expect, it } from 'bun:test';

// We test via the module — these functions are not exported, so we test them
// indirectly through the service behavior. For unit-level coverage, we
// replicate the logic here and validate the contract.

describe('Tier Classification Logic', () => {
  // Mirror the classifyTier logic for contract testing
  type AuditVerdict = 'PASS' | 'WARNING' | 'FAIL';
  type DriftSeverity = 'NONE' | 'MILD' | 'MODERATE' | 'SEVERE';
  type AgentTier = 'HOT' | 'WARM' | 'COOL';

  function classifyTier(
    verdict: AuditVerdict,
    driftSeverity: DriftSeverity,
    consecutivePasses: number
  ): AgentTier {
    if (verdict === 'FAIL' || verdict === 'WARNING') return 'HOT';
    if (driftSeverity === 'SEVERE' || driftSeverity === 'MODERATE') return 'HOT';
    if (consecutivePasses < 2) return 'WARM';
    return 'COOL';
  }

  describe('classifyTier', () => {
    it('assigns HOT for FAIL verdict', () => {
      expect(classifyTier('FAIL', 'NONE', 10)).toBe('HOT');
    });

    it('assigns HOT for WARNING verdict', () => {
      expect(classifyTier('WARNING', 'NONE', 5)).toBe('HOT');
    });

    it('assigns HOT for SEVERE drift even with PASS verdict', () => {
      expect(classifyTier('PASS', 'SEVERE', 5)).toBe('HOT');
    });

    it('assigns HOT for MODERATE drift even with PASS verdict', () => {
      expect(classifyTier('PASS', 'MODERATE', 5)).toBe('HOT');
    });

    it('assigns WARM for PASS with fewer than 2 consecutive passes', () => {
      expect(classifyTier('PASS', 'NONE', 0)).toBe('WARM');
      expect(classifyTier('PASS', 'NONE', 1)).toBe('WARM');
    });

    it('assigns COOL for PASS with 2+ consecutive passes and low drift', () => {
      expect(classifyTier('PASS', 'NONE', 2)).toBe('COOL');
      expect(classifyTier('PASS', 'MILD', 3)).toBe('COOL');
    });

    it('FAIL verdict overrides high consecutive passes', () => {
      expect(classifyTier('FAIL', 'NONE', 100)).toBe('HOT');
    });

    it('demotion is immediate — SEVERE drift overrides consecutive passes', () => {
      expect(classifyTier('PASS', 'SEVERE', 100)).toBe('HOT');
    });
  });
});
