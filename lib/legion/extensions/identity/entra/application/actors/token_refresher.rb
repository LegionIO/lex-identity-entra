# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module Application
          module Actor
            class TokenRefresher < Legion::Extensions::Actors::Every
              DEFAULT_REFRESH_INTERVAL = 2700

              def runner_class    = self.class
              def runner_function = 'manual'
              def use_runner?     = false
              def check_subtask?  = false
              def generate_task?  = false
              def run_now?        = false

              def time
                Legion::Settings.dig(:identity, :entra, :application, :token, :refresh_interval) ||
                  DEFAULT_REFRESH_INTERVAL
              end

              def enabled? # rubocop:disable Legion/Extension/ActorEnabledSideEffects
                true
              end

              def manual
                log.debug('Application TokenRefresher tick')
                data = Legion::Extensions::Identity::Entra::Helpers::TokenManager.token_data(:application, refresh: false)

                if data && !Legion::Extensions::Identity::Entra::Helpers::TokenManager.expired?(data)
                  log.debug('Application token still valid')
                  return
                end

                log.info('Application token nearing expiry, re-acquiring')
                auth_settings = Legion::Extensions::Identity::Entra::Helpers::TokenManager.settings_auth
                runner = Object.new.extend(Legion::Extensions::Identity::Entra::Application::Runners::Credential)
                result = runner.acquire_token(
                  tenant_id:     auth_settings[:tenant_id],
                  client_id:     auth_settings[:client_id],
                  client_secret: auth_settings[:client_secret]
                )

                body = result&.dig(:result)
                unless body&.dig(:access_token)
                  log.warn('Application token re-acquisition failed')
                  return
                end

                Legion::Extensions::Identity::Entra::Helpers::TokenManager.save_token(
                  :application,
                  access_token: body[:access_token],
                  expires_in:   body[:expires_in],
                  scopes:       body[:scope] || 'https://graph.microsoft.com/.default',
                  tenant_id:    auth_settings[:tenant_id],
                  client_id:    auth_settings[:client_id]
                )
                Legion::Extensions::Identity::Entra::Client.reset!(pattern: :application)
                log.info('Application token refreshed successfully')
              rescue StandardError => e
                log.error("Application TokenRefresher: #{e.message}")
              end
            end
          end
        end
      end
    end
  end
end
