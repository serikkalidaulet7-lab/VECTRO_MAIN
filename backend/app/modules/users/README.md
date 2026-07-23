# Users module

The Users module owns Vectro's user domain boundary. It will contain user-focused
business rules and the adapters required to expose and persist them.

- `domain` will hold technology-independent user business concepts and rules.
- `application` will coordinate user use cases through commands, queries, and ports.
- `infrastructure` will contain persistence and external-service adapters.
- `api` will adapt HTTP requests and responses to application use cases.
