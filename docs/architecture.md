# Architecture

## Repository Layout

```text
apps/
  api/
    src/
      server.ts
      pipeline/
      routes/
      types/
  extension/
docs/
```

## Runtime Architecture

### Browser Side

- Extract lightweight signals from the active page
- Send normalized features to backend
- Render a small user-facing warning state

### Backend Side

- Validate and normalize incoming feature payload
- Score with rule engine
- Score with LLM analyzer
- Combine scores and route the decision
- Return explainable output to the extension

The rule engine also applies brand-domain verification for common Taiwan-facing brands so that pages mentioning a trusted local brand on an unrelated hostname can be escalated more aggressively.

## Hybrid Decision Path

```text
Page Features
  -> Rule Engine
  -> LLM Analyzer
  -> Weighted Scoring
  -> Router
     -> allow
     -> warn
     -> escalate
```

## Planned Email Support

The current scaffold is web-first. Email support can be added by introducing mailbox-specific adapters:

- Gmail content script / add-on integration
- Outlook add-in integration
- Shared feature schema for message metadata, link metadata, and auth headers

## Planned Agent Services

The agent layer should be implemented as tool-driven services behind a queue or workflow runner, not directly in the extension. That keeps browser latency stable and avoids tying risky operations to the client.
