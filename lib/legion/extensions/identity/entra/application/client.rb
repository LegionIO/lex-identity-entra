# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module Application
          class Client < Legion::Extensions::Identity::Entra::Client
            def pattern = :application

            private

            def authenticate
              settings = auth_settings
              return unless settings[:tenant_id] && settings[:client_id] && settings[:client_secret]

              requested = Legion::Extensions::Identity::Entra::Helpers::Scopes.resolve(pattern: :application)
              registry.record_requested(requested)

              runner = Object.new.extend(Legion::Extensions::Identity::Entra::Application::Runners::Credential)
              result = runner.acquire_token(
                tenant_id:     settings[:tenant_id],
                client_id:     settings[:client_id],
                client_secret: settings[:client_secret]
              )
              body = result&.dig(:result)
              return unless body&.dig(:access_token)

              granted = body[:scope] || 'https://graph.microsoft.com/.default'
              registry.record_granted(granted)
              Legion::Extensions::Identity::Entra::Helpers::TokenManager.save_token(
                :application,
                access_token: body[:access_token],
                expires_in:   body[:expires_in],
                scopes:       granted,
                tenant_id:    settings[:tenant_id],
                client_id:    settings[:client_id]
              )
            end
          end
        end
      end
    end
  end
end
