# Backend Application Architecture

- `core` contains cross-cutting infrastructure such as configuration, logging, security, and database setup.
- `modules` contains self-contained product features as they are introduced.
- `shared` contains reusable exceptions, dependencies, and utility code used across modules.
