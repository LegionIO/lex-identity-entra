# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module Delegated
          class Client < Legion::Extensions::Identity::Entra::Client
            def pattern = :delegated

            private

            def authenticate
              settings = auth_settings
              return unless settings[:tenant_id] && settings[:client_id]

              requested = Legion::Extensions::Identity::Entra::Helpers::Scopes.resolve(pattern: :delegated)
              registry.record_requested(requested)

              browser = Legion::Extensions::Identity::Entra::Helpers::BrowserAuth.new(
                tenant_id: settings[:tenant_id],
                client_id: settings[:client_id],
                scopes:    requested
              )
              result = browser.authenticate
              body = result&.dig(:result)
              return unless body&.dig(:access_token)

              granted = body[:scope] || requested
              registry.record_granted(granted)
              Legion::Extensions::Identity::Entra::Helpers::TokenManager.save_token(
                :delegated,
                access_token:  body[:access_token],
                refresh_token: body[:refresh_token],
                expires_in:    body[:expires_in],
                scopes:        granted,
                tenant_id:     settings[:tenant_id],
                client_id:     settings[:client_id]
              )
            end
          end
        end
      end
    end
  end
end
