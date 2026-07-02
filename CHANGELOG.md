# Changelog

## [Unreleased]

## [0.5.1] - 2026-07-02

### Fixed
- Align delegated Broker provider lookup with registration (issue #5). `TokenManager.from_broker` now requests the `:entra_delegated` provider name that `AuthValidator#register_broker` registers; previously it asked Broker for `:entra`, and because Broker provider names are exact keys the delegated token fallback missed the registered provider. Application, workload, and managed-identity token paths are unchanged.

## [0.5.0] - 2026-07-02

### Added
- Opt-in `:mail` delegated scope category (`Mail.Read` + `Mail.Send` only) for the lex-outlook build (ADR-0005). Least privilege: excludes `Mail.ReadWrite`, `MailboxSettings.Read`, and `Mail.Read.Shared`. Not a member of the default-enabled `:microsoft_graph` category, so existing delegated/Teams installs are unaffected.

### Note
- Enabling `:mail` in `identity.entra.delegated.scopes.enabled_categories` changes the delegated `scope_fingerprint` and forces a **one-time re-consent** for that qualifier. This is expected behavior (least-privilege scope opt-in), not an error.

## [0.4.1] - 2026-05-18

### Fixed
- Require resolved identity before vault operations; prevents 403 errors from writing to placeholder paths

## [0.4.0] - 2026-05-18

### Fixed
- Token refresher actors (workload_identity, application, managed_identity) no longer activate when credentials are absent; eliminates noisy WARN/INFO spam on local dev.
- Vault read/write operations now require a resolved canonical name before constructing vault paths; prevents 403 errors from writing to `users/anonymous/...` or `users/default/...` before identity resolves.
- Removed `'default'` fallback from `vault_path`; returns nil when canonical name is unavailable.

### Changed
- `canonical_name_available?` helper added to TokenManager; guards all vault operations and backfill logic.
- Tokens save to local disk first, backfill to vault once identity resolves to real canonical name.

## [0.3.1] - 2026-05-15

### Fixed
- `refresh_token` returned `from_local_data` after saving, which is nil when vault succeeded and deleted the disk file. Now returns `from_memory` so the caller always gets the refreshed token without triggering a redundant browser re-auth on restart.

## [0.3.0] - 2026-05-14

### Added
- Delegated token persistence to HashiCorp Vault at `kv/data/users/<identity>/entra/delegated/auth`; disk file used only as fallback when Vault is unavailable.
- Automatic backfill: existing disk tokens are migrated to Vault on next load and the disk file is deleted once Vault write succeeds.
- `delete_local` cleans up the on-disk token file whenever Vault becomes authoritative.
- `AuthValidator` calls `Legion::Identity::Broker.register_provider` after successful auth so any extension can call `Legion::Identity::Broker.token_for(:entra_delegated, qualifier: :delegated)`.
- `AuthValidator` calls `Legion::Identity::Resolver.upgrade!` after auth to promote the Entra-verified identity into `Legion::Identity::Process` state.
- MD5 scope fingerprint stored with token across all backends; mismatch or missing fingerprint forces re-authentication.
- In-memory token store as tertiary fallback (vault → disk → memory).
- Delegated scopes expanded to full org-granted permission set: Teams, Chat, Channel, OnlineMeetings, OneNote, SharePoint, Yammer, Files, Presence, and core OpenID/profile scopes.
- OAuth callback page auto-closes after 10-second JavaScript countdown.

### Changed
- Vault read skipped at boot until process identity is trusted (prevents 403 during resolver race).
- Vault read/write now use `Legion::Crypt.get`/`Legion::Crypt.write` via the `kv` mount directly, matching the policy path.
- `AuthValidator` delay reduced from 90s to 9s.

## [0.2.0] - 2026-05-07

### Added
- Browser OAuth with PKCE, local callback handling, and device-code fallback for delegated Entra auth.
- Microsoft identity OAuth runner for client credentials, authorization code, device code, and refresh-token grants.
- CLI auth entrypoint and manifest metadata for `legion lex exec entra auth login/status`.
- Refresh-aware token persistence with Vault, local file, and Broker fallback lookup.
- Multi-account Entra discovery for delegated, secondary, and privileged account token qualifiers.

### Changed
- `resolve_all` now uses discovered Entra token qualifiers instead of wrapping only the default delegated account.
- `provide_token` includes qualifier and scope metadata from the persisted token record.

## [0.1.0] - 2026-04-24

### Added
- Initial Entra identity provider scaffold with cached-token Graph `/me` resolution.
