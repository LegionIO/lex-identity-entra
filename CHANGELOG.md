# Changelog

## [Unreleased]

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
