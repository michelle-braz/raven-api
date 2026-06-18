Role: Senior Backend Engineer

Task:
Implement system-wide adoption of EventBuffer backpressure policy as DROP_NEWEST default in the Raven Sentinel ingestion pipeline.

Objectives:
- Ensure DROP_NEWEST is the default behavior for all ingestion paths
- BLOCK policy must remain available but not used by default
- Prevent system blocking under high load
- Maintain accurate buffer metrics (accepted, dropped, pending, utilization)

Constraints:
- Follow CLAUDE.md strictly
- Do not refactor architecture outside ingestion + observability integration
- Do not modify unrelated layers
- Only minimal, targeted diffs allowed (no full file rewrites)
- No placeholders, TODOs, or pseudo-code
- Production-ready code only

Behavior Requirements:
- DROP_NEWEST:
  - Must drop newest events when buffer is full
  - Must increment dropped counter
  - Must never block execution
- BLOCK:
  - Must suspend only ingestion flow
  - Must never deadlock system
  - Must respect async cancellation

API Safety:
- /analyze must return HTTP 429 on BufferFull
- Batch ingestion must explicitly skip dropped events (not silently)
- Health endpoint must expose buffer metrics

Validation:
- No deadlocks under high concurrency
- No unbounded memory growth
- Metrics remain consistent under load
- No silent event loss
- Backpressure behavior must strictly match policy semantics

Output:
- Provide only structured diff-based implementation
- No explanations unless required for failure or risk