# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module WorkloadIdentity
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
                Legion::Settings.dig(:identity, :entra, :workload_identity, :token, :refresh_interval) ||
                  DEFAULT_REFRESH_INTERVAL
              end

              def enabled? # rubocop:disable Legion/Extension/ActorEnabledSideEffects
                ENV['AZURE_TENANT_ID'] && ENV['AZURE_CLIENT_ID'] && ENV['AZURE_FEDERATED_TOKEN_FILE']
              end

              def manual
                log.debug('WorkloadIdentity TokenRefresher tick')
                data = Legion::Extensions::Identity::Entra::Helpers::TokenManager.token_data(:workload_identity, refresh: false)

                if data && !Legion::Extensions::Identity::Entra::Helpers::TokenManager.expired?(data)
                  log.debug('Workload identity token still valid')
                  return
                end

                log.info('Workload identity token nearing expiry, re-acquiring via federation')
                runner = Object.new.extend(Legion::Extensions::Identity::Entra::WorkloadIdentity::Runners::Token)
                result = runner.acquire_from_environment

                body = result&.dig(:result)
                unless body&.dig(:access_token)
                  log.warn('Workload identity token re-acquisition failed')
                  return
                end

                Legion::Extensions::Identity::Entra::Helpers::TokenManager.save_token(
                  :workload_identity,
                  access_token: body[:access_token],
                  expires_in:   body[:expires_in],
                  scopes:       'https://graph.microsoft.com/.default'
                )
                Legion::Extensions::Identity::Entra::Client.reset!(pattern: :workload_identity)
                log.info('Workload identity token refreshed successfully')
              rescue StandardError => e
                log.error("WorkloadIdentity TokenRefresher: #{e.message}")
              end
            end
          end
        end
      end
    end
  end
end
