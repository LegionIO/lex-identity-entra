# lex-identity-entra

LegionIO identity provider extension for Microsoft Entra ID (Azure AD). Implements the unified
identity provider contract for delegated (user), application (client credentials), managed identity,
and workload identity authentication patterns.

## Features

- **Delegated auth** — OAuth2 PKCE browser flow with local callback server; device-code fallback
- **Token persistence** — in-memory by default; Vault (`kv/data/users/<identity>/entra/<qualifier>/auth`) reading and writing are separate opt-ins via `vault_read_enabled` / `vault_write_enabled`. Tokens are never written to local disk
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
        auto_authenticate: false   # set true to open browser automatically (boot + token refresher)
        callback_timeout: 120
        # Guard for automatic (actor-initiated) sign-in:
        backoff_base_seconds: 1800      # wait after an unanswered tab; doubles each time
        backoff_max_seconds: 21600
        max_auto_attempts: 3            # then stop opening tabs until you sign in manually
        skip_when_screen_locked: true   # macOS: never open tabs while the screen is locked
        skip_when_idle_seconds: 900     # macOS: skip if no keyboard/mouse input for this long (0 = off)
      token:
        vault_read_enabled: false   # set true to read the token from Vault
        vault_write_enabled: false  # set true to write the token to Vault
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

Interactive sign-in is protected by `Helpers::InteractiveAuthGuard`:

- **Single-flight**: only one browser/device-code attempt runs at a time, per process (mutex) and across
  processes (`flock` on `~/.legionio/run/entra_browser_auth.lock`).
- **Backoff**: when an automatic attempt times out, the next one waits `backoff_base_seconds` (default 30 min),
  doubling up to `backoff_max_seconds`. After `max_auto_attempts` unanswered tabs, automatic sign-in pauses
  until you sign in manually (`legionio auth teams` or `legion lex exec entra auth login`). Backoff state is
  kept in `~/.legionio/run/entra_browser_auth_state.json` (no secrets), so restarting the daemon does not
  reopen a tab right away.
- **Presence**: on macOS, automatic attempts are skipped while the screen is locked or the user is idle.
- **No refresh storms**: a refresh token that Microsoft rejects (`invalid_grant` and similar) is not retried
  until a new token is saved, and transient refresh errors back off from 30 s up to 15 min. One warning tells
  you how to sign in again.
- `TokenRefresher` only opens a browser when `auto_authenticate: true`.

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
| `mail` | Mailbox access for lex-outlook: `Mail.Read` + `Mail.Send` only (opt-in) |
| `teams` | Teams, Chat, Channel, OnlineMeetings, Presence, Activity |
| `one_note` | OneNote notebook read/write |
| `sharepoint` | SharePoint/OneDrive files and sites |
| `azure_communication_services` | Teams calls and chat management |
| `yammer` | Viva Engage / Yammer communities and conversations |

> **Note on `:mail`** — the `mail` category is opt-in and is **not** part of the
> default-enabled `microsoft_graph` set, so existing delegated installs see no scope
> change. Adding `mail` to `identity.entra.delegated.scopes.enabled_categories` changes
> the delegated `scope_fingerprint` and forces a **one-time re-consent** for that
> qualifier on next boot. This is expected least-privilege behavior, not an error.

## Token storage

| Backend | Path | When used |
|---------|------|-----------|
| HashiCorp Vault | `kv/data/users/<identity>/entra/delegated/auth` | Only when opted in: `vault_read_enabled` / `vault_write_enabled` (both default `false`) |
| Memory | In-process store | Default persistence; tokens are never written to local disk |

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
