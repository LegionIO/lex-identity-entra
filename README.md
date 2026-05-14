# lex-identity-entra

LegionIO identity provider extension for Microsoft Entra ID (Azure AD). Implements the unified
identity provider contract for delegated (user), application (client credentials), managed identity,
and workload identity authentication patterns.

## Features

- **Delegated auth** — OAuth2 PKCE browser flow with local callback server; device-code fallback
- **Token persistence** — Vault-first (`kv/data/users/<identity>/entra/<qualifier>/auth`), disk fallback, in-memory fallback; disk file deleted once Vault write succeeds
- **Scope fingerprinting** — MD5 fingerprint of active scopes stored with token; any scope change forces re-authentication on next boot
- **Identity integration** — `AuthValidator` upgrades `Legion::Identity::Process` via `Resolver.upgrade!` and registers with `Legion::Identity::Broker` for cross-extension token access
- **Application credentials** — client credentials flow for service-to-service auth
- **Managed Identity** — Azure IMDS token acquisition for hosted workloads
- **Workload Identity** — federated credential support for Kubernetes and CI/CD

## Installation

Add to your `Gemfile`:

```ruby
gem 'lex-identity-entra'
```

## Configuration

```yaml
# ~/.legionio/settings/identity.yml
identity:
  entra:
    auth:
      tenant_id: "your-tenant-id"
      client_id: "your-client-id"
    delegated:
      browser_auth:
        auto_authenticate: false   # set true to open browser automatically at boot
        callback_timeout: 120
      token:
        refresh_buffer: 60
        refresh_interval: 900
      scopes:
        enabled_categories:
          - microsoft_graph
          - teams
          - one_note
          - sharepoint
          - azure_communication_services
          - yammer
```

## Usage

### Delegated (user) authentication

```bash
# Via CLI
legion lex exec entra auth login
legion lex exec entra auth status
```

The `AuthValidator` actor fires 9 seconds after boot. If `auto_authenticate: true` is set,
it opens a browser window automatically. Otherwise trigger login via the CLI.

### Accessing tokens from another extension

```ruby
token = Legion::Identity::Broker.token_for(:entra_delegated, qualifier: :delegated)
```

### Application (client credentials)

```yaml
identity:
  entra:
    application:
      tenant_id: "your-tenant-id"
      client_id: "your-client-id"
      client_secret: "your-client-secret"  # or use Vault
```

## Scope categories

| Category | Description |
|----------|-------------|
| `microsoft_graph` | Core Graph API: User.Read, Files, Devices, OpenID scopes |
| `teams` | Teams, Chat, Channel, OnlineMeetings, Presence, Activity |
| `one_note` | OneNote notebook read/write |
| `sharepoint` | SharePoint/OneDrive files and sites |
| `azure_communication_services` | Teams calls and chat management |
| `yammer` | Viva Engage / Yammer communities and conversations |

## Token storage

| Backend | Path | Priority |
|---------|------|----------|
| HashiCorp Vault | `kv/data/users/<identity>/entra/delegated/auth` | 1 (preferred) |
| Local disk | `~/.legionio/tokens/entra_delegated.json` | 2 (fallback, deleted when Vault succeeds) |
| Memory | In-process store | 3 (runtime fallback) |

## Identity provider contract

```ruby
{
  canonical_name:    "jdoe",       # normalized from onPremisesSamAccountName or mailNickname
  kind:              :human,
  source:            :entra_delegated,
  provider_identity: "object-id-guid",
  profile:           { ... }           # full Graph /me response
}
```

## Development

```bash
bundle install
bundle exec rspec
bundle exec rubocop
```

**GitHub**: https://github.com/LegionIO/lex-identity-entra
