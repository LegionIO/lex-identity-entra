# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module ManagedIdentity
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
                Legion::Settings.dig(:identity, :entra, :managed_identity, :token, :refresh_interval) ||
                  DEFAULT_REFRESH_INTERVAL
              end

              def enabled? # rubocop:disable Legion/Extension/ActorEnabledSideEffects
                true
              end

              def manual
                log.debug('ManagedIdentity TokenRefresher tick')
                data = Legion::Extensions::Identity::Entra::Helpers::TokenManager.token_data(:managed_identity, refresh: false)

                if data && !Legion::Extensions::Identity::Entra::Helpers::TokenManager.expired?(data)
                  log.debug('Managed identity token still valid')
                  return
                end

                log.info('Managed identity token nearing expiry, re-acquiring from IMDS')
                runner = Object.new.extend(Legion::Extensions::Identity::Entra::ManagedIdentity::Runners::Token)
                result = runner.acquire_managed_token

                body = result&.dig(:result)
                unless body&.dig(:access_token)
                  log.warn('Managed identity token re-acquisition failed')
                  return
                end

                Legion::Extensions::Identity::Entra::Helpers::TokenManager.save_token(
                  :managed_identity,
                  access_token: body[:access_token],
                  expires_in:   body[:expires_in] || body[:expires_on]&.then { |t| t.to_i - Time.now.to_i },
                  scopes:       'https://graph.microsoft.com/.default'
                )
                Legion::Extensions::Identity::Entra::Client.reset!(pattern: :managed_identity)
                log.info('Managed identity token refreshed successfully')
              rescue StandardError => e
                log.error("ManagedIdentity TokenRefresher: #{e.message}")
              end
            end
          end
        end
      end
    end
  end
end
