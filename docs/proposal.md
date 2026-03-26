# ScamNoMom Proposal

## 1. Overview

ScamNoMom is designed to detect phishing across email, websites, and future messaging channels. The system uses a hybrid architecture that balances speed, cost, explainability, and deeper reasoning when the risk level is ambiguous.

## 2. Design Principle

The core principle is conditional escalation:

- Rules handle obvious patterns quickly.
- LLM analysis handles semantic ambiguity.
- Agent analysis is invoked only for uncertain cases.
- A learning system improves policy and model quality over time.

This avoids routing every request into a slow and expensive agent pipeline.

## 3. System Flow

```text
Data Capture
  -> Feature Extraction
  -> Rule Engine
  -> LLM Analyzer
  -> Risk Scoring
  -> Decision Router
     -> Pass
     -> Warn
     -> Agent Deep Analysis
          -> Re-score
          -> Final Output
  -> User Feedback
  -> Learning System
```

## 4. Core Modules

### Feature Extraction

Email inputs:

- Sender identity
- Reply-To mismatch
- SPF / DKIM / DMARC results
- HTML structure
- Links and attachment metadata

Web inputs:

- DOM signals
- Password and input forms
- Redirect patterns
- Link destinations
- Hidden or spoofing-related CSS patterns

### Rule Engine

Rules provide a deterministic score from 0 to 100 based on high-signal security heuristics:

- Domain mismatch
- Suspicious TLD
- Authentication failures
- Link text and destination mismatch
- External form submission

### LLM Analyzer

The LLM consumes text plus a normalized feature summary and returns:

- `riskLevel`
- `score`
- `reasons`
- `attackType`
- `confidence`

### Risk Scoring

Initial score formula:

```text
finalScore = 0.4 * ruleScore + 0.6 * llmScore
```

This weight can later be tuned from offline evaluation and user feedback.

### Decision Router

- `0-39`: allow
- `40-69`: escalate to agent
- `70-100`: warn immediately

### Agent Layer

The agent is only used for borderline cases. Planned tools:

- WHOIS lookup
- Brand-domain verification
- Blacklist lookup
- Redirect-chain tracing
- Safe sandbox link simulation

### Final Output

```json
{
  "riskLevel": "high",
  "score": 82,
  "reasons": ["Domain mismatch", "Credential request"],
  "confidence": 0.88,
  "recommendedAction": "block"
}
```

## 5. Learning System

Data sources:

- Public phishing datasets
- User feedback
- Plugin telemetry with privacy controls
- Weak labels from LLM analysis

Training loop:

1. Collect samples
2. Generate weak labels
3. Review a subset with humans
4. Fine-tune models
5. Deploy
6. Optimize policy with reinforcement learning

## 6. RL Framing

State:

- Rule score
- LLM score
- Agent output
- Context features

Action:

- Allow
- Warn
- Strong warn
- Block

Reward:

- Correctly block phishing: `+10`
- Correctly warn: `+5`
- False positive: `-3`
- Missed phishing: `-10`

## 7. MVP Plan

Phase 1:

- Rule engine
- Chrome Extension
- Basic web feature extraction

Phase 2:

- LLM integration
- Explainable risk output

Phase 3:

- Feedback collection
- Data storage and analytics

Phase 4:

- Agent tools
- RL-based action optimization

## 8. Risks

- False positives harming trust
- Agent latency on escalated cases
- Sensitive-content privacy handling
- Brand spoofing edge cases

## 9. Success Metrics

- Detection rate above 90%
- False positive rate below 5%
- Low enough latency for in-browser use
- Actionable explanations that users understand
