# Factory Rules

## Protected Areas
- core/
- deployment/
- observability/
- tooling/

## Forbidden
- no architecture rewrites
- no speculative abstractions
- no stack replacement
- no duplicate infrastructure logic
- no hidden coupling

## Required
- use SDK interfaces only
- preserve modularity
- keep business logic inside apps/modules
- prioritize deterministic systems
- use standard logging/config systems

## Engineering Principles
- infrastructure before features
- observability before optimization
- simple solutions before abstractions
- reusable primitives before specialization

## Critical Rules
- do not create abstractions without at least two real use cases
- when uncertain, prefer simpler deterministic implementations