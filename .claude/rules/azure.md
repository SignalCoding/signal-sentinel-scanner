---
paths: ["**/*.bicep", "**/*.bicepparam", "**/azure/**", "**/infra/**", "**/Program.cs", "**/*Client.cs", "**/*HttpClient*.cs"]
---
# Scoped Rule: Azure Identity, Outbound Calls and App Service (CONSTITUTION #29)

## Identity in production code
- Construct `ManagedIdentityCredential` (with the client ID of the user-assigned identity where one
  is used); never `DefaultAzureCredential`, whose probe chain succeeds with whatever developer
  credential it finds.
- Startup guard in `Program.cs`: resolve the credential and acquire one token for the first
  protected dependency (Key Vault, SQL, the model endpoint) before the app serves; a missing or
  wrong identity ends the process with a specific logged error. The guard is skipped only under an
  explicit `Development` flag the deployment pipeline cannot set.
- Local development selects a separate, named path by environment: `AzureCliCredential` or a
  connection string from User Secrets. The CLI login must hold the same roles the Managed Identity
  holds, or a passing local test proves nothing about production authorisation.

## Outbound endpoint allow-list
- Every `HttpClient` that calls a model or a third-party API is a named typed client whose base
  address comes from configuration, with a delegating handler that refuses any request whose host
  is not in `AllowedOutboundHosts` (enumerated in `_docs/ai/configuration.md`, no wildcards).
  Redirects to another host, model-requested fetches and config typos fail closed.
- One architecture test asserts every registered typed client carries the handler; one negative
  test asserts a request to `attacker.example` is refused before a socket opens.
- Adding a host is a spec-visible change routed to `coding-agent-security` and logged with
  `scripts/log-decision.sh`, naming the reason and the data that will cross it.

## Infrastructure and the CLI
- Every resource name, resource group and region a script or test depends on is read from one
  place (configuration or the Bicep parameter file), never retyped in a command.
- Bicep that owns `appsettings` replaces the whole collection: either every setting is in the
  template, or the template reads the live collection before writing.
- `az webapp config appsettings set` restarts the app by itself; do not follow it with
  `az webapp restart`.
- `az webapp config ssl create` (managed certificate) can report a JSON decode error while
  succeeding; check the certificate state before retrying, and prefer the REST PUT for a
  scriptable path.
- Treat "the docs say X" about any deployed resource as a hypothesis until a live check agrees
  (`az ... show`, or `curl -sI` of the endpoint); cite the live check, not the doc.
