# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module Delegated
          module Actor
            class TokenRefresher < Legion::Extensions::Actors::Every
              DEFAULT_REFRESH_INTERVAL = 900

              def runner_class    = self.class
              def runner_function = 'manual'
              def use_runner?     = false
              def check_subtask?  = false
              def generate_task?  = false
              def run_now?        = false

              def time
                Legion::Settings.dig(:identity, :entra, :delegated, :token, :refresh_interval) ||
                  DEFAULT_REFRESH_INTERVAL
              end

              def enabled? # rubocop:disable Legion/Extension/ActorEnabledSideEffects
                true
              end

              def manual
                log.debug('Delegated TokenRefresher tick')
                data = stored_raw_data

                unless data && data[:refresh_token]
                  log.debug('No stored delegated token with refresh_token, skipping refresh')
                  return
                end

                unless Legion::Extensions::Identity::Entra::Helpers::TokenManager.expired?(data) ||
                       Legion::Extensions::Identity::Entra::Helpers::TokenManager.scope_fingerprint_stale?(:delegated, data)
                  log.debug('Delegated token still valid')
                  return
                end

                log.info('Delegated token expired or stale, refreshing')
                refreshed = Legion::Extensions::Identity::Entra::Helpers::TokenManager.token_data(:delegated, refresh: true)
                if refreshed && !Legion::Extensions::Identity::Entra::Helpers::TokenManager.expired?(refreshed)
                  Legion::Extensions::Identity::Entra::Client.reset!(pattern: :delegated)
                  log.info('Delegated token refreshed successfully')
                elsif auto_authenticate?
                  log.info('Delegated token refresh failed, attempting automatic browser re-auth')
                  attempt_browser_reauth
                else
                  log.debug('[entra][token_refresher] action=reauth_skipped reason=auto_authenticate_disabled')
                  auth_guard.notify_reauth_required('token_refresh_failed')
                end
              rescue StandardError => e
                handle_exception(e, level: :error, operation: 'entra.delegated.token_refresher.manual')
              end

              private

              def auto_authenticate?
                Legion::Settings.dig(:identity, :entra, :delegated, :browser_auth, :auto_authenticate) == true
              end

              def auth_guard
                Legion::Extensions::Identity::Entra::Helpers::InteractiveAuthGuard
              end

              def stored_raw_data
                Legion::Extensions::Identity::Entra::Helpers::TokenManager.from_vault_data(:delegated) ||
                  Legion::Extensions::Identity::Entra::Helpers::TokenManager.from_memory(:delegated)
              end

              def attempt_browser_reauth
                auth_settings = Legion::Extensions::Identity::Entra::Helpers::TokenManager.settings_auth
                return unless auth_settings[:tenant_id] && auth_settings[:client_id]

                scopes = Legion::Extensions::Identity::Entra::Helpers::Scopes.resolve(pattern: :delegated)
                browser = Legion::Extensions::Identity::Entra::Helpers::BrowserAuth.new(
                  tenant_id: auth_settings[:tenant_id],
                  client_id: auth_settings[:client_id],
                  scopes:    scopes,
                  automatic: true
                )

                result = browser.authenticate
                body = result&.dig(:result)
                unless body&.dig(:access_token)
                  log.debug("[entra][token_refresher] action=reauth_incomplete error=#{result&.dig(:error)} reason=#{result&.dig(:reason)}")
                  return
                end

                Legion::Extensions::Identity::Entra::Helpers::TokenManager.save_token(
                  :delegated,
                  access_token:  body[:access_token],
                  refresh_token: body[:refresh_token],
                  expires_in:    body[:expires_in],
                  scopes:        body[:scope] || scopes,
                  tenant_id:     auth_settings[:tenant_id],
                  client_id:     auth_settings[:client_id]
                )
                Legion::Extensions::Identity::Entra::Client.reset!(pattern: :delegated)
                log.info('Delegated auth restored via browser re-auth')
              rescue StandardError => e
                handle_exception(e, level: :error, operation: 'entra.delegated.token_refresher.attempt_browser_reauth')
              end
            end
          end
        end
      end
    end
  end
end
