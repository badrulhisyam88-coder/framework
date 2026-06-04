"""Execution runtime.

Phase 39 introduced this package to make the topology evolve over time
in response to operator action. Phase 49 added real-probe execution
(`_runner_from_probe`). Phase 59b removed the original canned-script
mechanism — every execution now requires a real probe_runner that
emits StageEvent + ResultEvent records based on real HTTP traffic.

The runner consumes the event stream, materializes StageState and
ResultState records on the investigation's ExecutionRun, and surfaces
them on the topology via pseudo-nodes in the branch serializer.

No LLM. No autonomous reasoning. Pure event-driven state transitions
over a real probe stream.
"""
