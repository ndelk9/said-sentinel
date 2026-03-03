import { describe, expect, it, mock, beforeEach, afterEach } from "bun:test";

// These functions are not exported from plugin.ts, so we replicate the logic
// for contract testing (same pattern as tier-classification.test.ts).

type AuditVerdict = "PASS" | "WARNING" | "FAIL";
type FindingSeverity = "LOW" | "MEDIUM" | "HIGH";
interface AuditFinding {
  issue: string;
  severity: FindingSeverity;
  remediation: string;
}

function verdictToFeedbackScore(
  verdict: AuditVerdict,
  confidenceScore: number,
): number {
  const c = Math.max(0, Math.min(1, confidenceScore));
  if (verdict === "PASS") return Math.round(65 + c * 30);
  if (verdict === "WARNING") return Math.round(30 + c * 25);
  return Math.round(25 - c * 20);
}

function generateFeedbackComment(
  verdict: AuditVerdict,
  findings: AuditFinding[],
  confidenceScore: number,
): string {
  const highCount = findings.filter((f) => f.severity === "HIGH").length;
  const medCount = findings.filter((f) => f.severity === "MEDIUM").length;
  const topIssues = findings.slice(0, 3).map((f) => f.issue);

  if (verdict === "PASS") {
    return `PASS (confidence ${(confidenceScore * 100).toFixed(0)}%): Identity verified, no critical findings.`;
  }
  if (verdict === "FAIL") {
    return `FAIL: ${highCount} critical finding(s). ${topIssues.join("; ")}`;
  }
  return `WARNING: ${medCount} moderate finding(s), confidence ${(confidenceScore * 100).toFixed(0)}%. ${topIssues.join("; ")}`;
}

const FEEDBACK_COOLDOWN_MS = 24 * 60 * 60 * 1000;

describe("Feedback Submission", () => {
  describe("verdictToFeedbackScore", () => {
    it("returns 65-95 for PASS verdicts", () => {
      expect(verdictToFeedbackScore("PASS", 0.0)).toBe(65);
      expect(verdictToFeedbackScore("PASS", 0.5)).toBe(80);
      expect(verdictToFeedbackScore("PASS", 1.0)).toBe(95);
    });

    it("returns 30-55 for WARNING verdicts", () => {
      expect(verdictToFeedbackScore("WARNING", 0.0)).toBe(30);
      expect(verdictToFeedbackScore("WARNING", 0.5)).toBe(43);
      expect(verdictToFeedbackScore("WARNING", 1.0)).toBe(55);
    });

    it("returns 5-25 for FAIL verdicts (inverted: high confidence = lower score)", () => {
      expect(verdictToFeedbackScore("FAIL", 0.0)).toBe(25);
      expect(verdictToFeedbackScore("FAIL", 0.5)).toBe(15);
      expect(verdictToFeedbackScore("FAIL", 1.0)).toBe(5);
    });

    it("clamps confidence to 0-1 range", () => {
      expect(verdictToFeedbackScore("PASS", -0.5)).toBe(65);
      expect(verdictToFeedbackScore("PASS", 1.5)).toBe(95);
      expect(verdictToFeedbackScore("FAIL", 2.0)).toBe(5);
    });

    it("always returns an integer", () => {
      for (const verdict of ["PASS", "WARNING", "FAIL"] as AuditVerdict[]) {
        for (const c of [0, 0.1, 0.33, 0.5, 0.77, 0.9, 1.0]) {
          const score = verdictToFeedbackScore(verdict, c);
          expect(score).toBe(Math.floor(score));
        }
      }
    });

    it("PASS scores are always higher than WARNING scores", () => {
      for (const c of [0, 0.5, 1.0]) {
        expect(verdictToFeedbackScore("PASS", c)).toBeGreaterThan(
          verdictToFeedbackScore("WARNING", c),
        );
      }
    });

    it("WARNING scores are always higher than FAIL scores", () => {
      for (const c of [0, 0.5, 1.0]) {
        expect(verdictToFeedbackScore("WARNING", c)).toBeGreaterThan(
          verdictToFeedbackScore("FAIL", c),
        );
      }
    });
  });

  describe("generateFeedbackComment", () => {
    it("generates PASS comment with confidence", () => {
      const comment = generateFeedbackComment("PASS", [], 0.95);
      expect(comment).toContain("PASS");
      expect(comment).toContain("95%");
    });

    it("generates FAIL comment with finding count and issues", () => {
      const findings: AuditFinding[] = [
        { issue: "Not verified", severity: "HIGH", remediation: "Verify" },
        { issue: "No Passport NFT", severity: "HIGH", remediation: "Mint" },
      ];
      const comment = generateFeedbackComment("FAIL", findings, 0.9);
      expect(comment).toContain("FAIL");
      expect(comment).toContain("2 critical");
      expect(comment).toContain("Not verified");
      expect(comment).toContain("No Passport NFT");
    });

    it("generates WARNING comment with moderate finding count", () => {
      const findings: AuditFinding[] = [
        { issue: "Metadata stale", severity: "MEDIUM", remediation: "Update" },
      ];
      const comment = generateFeedbackComment("WARNING", findings, 0.7);
      expect(comment).toContain("WARNING");
      expect(comment).toContain("1 moderate");
      expect(comment).toContain("70%");
    });

    it("limits to top 3 issues in comment", () => {
      const findings: AuditFinding[] = Array.from({ length: 5 }, (_, i) => ({
        issue: `Issue ${i + 1}`,
        severity: "MEDIUM" as FindingSeverity,
        remediation: "Fix",
      }));
      const comment = generateFeedbackComment("WARNING", findings, 0.5);
      expect(comment).toContain("Issue 1");
      expect(comment).toContain("Issue 3");
      expect(comment).not.toContain("Issue 4");
    });
  });

  describe("Feedback cooldown logic", () => {
    it("24-hour cooldown constant is correct", () => {
      expect(FEEDBACK_COOLDOWN_MS).toBe(86400000);
    });

    it("cooldown comparison works correctly", () => {
      const now = Date.now();
      const recentFeedback = new Date(now - 3600000).toISOString(); // 1 hour ago
      const oldFeedback = new Date(now - 90000000).toISOString(); // 25 hours ago

      const recentDelta = now - new Date(recentFeedback).getTime();
      expect(recentDelta < FEEDBACK_COOLDOWN_MS).toBe(true); // should be blocked

      const oldDelta = now - new Date(oldFeedback).getTime();
      expect(oldDelta >= FEEDBACK_COOLDOWN_MS).toBe(true); // should be allowed
    });

    it("null lastFeedbackAt means feedback is allowed", () => {
      const lastFb: string | null = null;
      const lastFbTime = lastFb ? new Date(lastFb).getTime() : 0;
      expect(Date.now() - lastFbTime >= FEEDBACK_COOLDOWN_MS).toBe(true);
    });
  });

  describe("Score boundary invariants", () => {
    it("all scores are within 0-100", () => {
      const verdicts: AuditVerdict[] = ["PASS", "WARNING", "FAIL"];
      const confidences = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0];
      for (const v of verdicts) {
        for (const c of confidences) {
          const score = verdictToFeedbackScore(v, c);
          expect(score).toBeGreaterThanOrEqual(0);
          expect(score).toBeLessThanOrEqual(100);
        }
      }
    });

    it("verdict ordering is strict: PASS > WARNING > FAIL at any confidence", () => {
      const confidences = [0, 0.25, 0.5, 0.75, 1.0];
      for (const c of confidences) {
        const p = verdictToFeedbackScore("PASS", c);
        const w = verdictToFeedbackScore("WARNING", c);
        const f = verdictToFeedbackScore("FAIL", c);
        expect(p).toBeGreaterThan(w);
        expect(w).toBeGreaterThan(f);
      }
    });
  });
});
