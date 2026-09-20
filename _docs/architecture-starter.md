# Architecture Starter (Generic)

This document is a starting point for your project's architectural decisions. It captures stack-agnostic principles. As you choose a stack (during Gate 0) and develop the project, replace generic guidance with your actual decisions.

## 1. Architectural Layers

Most projects have some version of:

- **Interface layer** - how users (or other systems) interact with the application
- **Service / domain layer** - business logic
- **Data layer** - persistent storage and retrieval

For your project, define what these are concretely.

## 2. Data Access

Decisions to make:

- Where does data live? (RDBMS, document store, object storage)
- How is data accessed? (ORM, query builder, direct SQL, repository pattern)
- How are migrations managed?
- How is data classified (PII, sensitive, public)?

## 3. Error Handling

Decisions to make:

- Exception strategy (throw and catch, Result types, error codes)
- Logging strategy (structured, level-based, sampling)
- Error response format (for APIs: ProblemDetails, custom, RFC 7807)
- Sensitive data scrubbing in logs

## 4. Configuration

Decisions to make:

- Source of configuration (env vars, config files, secrets vault)
- Secrets management (NEVER in source; vault required)
- Per-environment overrides (dev, staging, production)

## 5. Testing

Decisions to make:

- Unit test framework
- Integration test framework
- E2E test framework (if applicable)
- Coverage targets
- Test data strategy (factories, fixtures, real data)

## 6. Deployment

Decisions to make:

- Target environment (cloud, on-prem, hybrid)
- CI/CD pipeline
- Rollback strategy
- Monitoring and observability
- Incident response

## 7. Security Architecture

Cross-references the master library's `owasp-2025-compliance` skill. For this project specifically:

- Authentication mechanism
- Authorisation model (RBAC, ABAC, ACL)
- Session management
- Rate limiting
- Audit logging

## Notes

Once you've chosen a stack, the corresponding architecture-starter.md from the stack-specific template will contain concrete recommendations rather than placeholders. You can either bootstrap that template alongside (and merge), or fill this file in manually based on the stack.
