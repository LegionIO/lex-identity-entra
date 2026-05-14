# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module ManagedIdentity
          class Client < Legion::Extensions::Identity::Entra::Client
            def pattern = :managed_identity

            private

            def authenticate
              registry.record_requested('https://graph.microsoft.com/.default')

              runner = Object.new.extend(Legion::Extensions::Identity::Entra::ManagedIdentity::Runners::Token)
              result = runner.acquire_managed_token
              body = result&.dig(:result)
              return unless body&.dig(:access_token)

              registry.record_granted('https://graph.microsoft.com/.default')
              Legion::Extensions::Identity::Entra::Helpers::TokenManager.save_token(
                :managed_identity,
                access_token: body[:access_token],
                expires_in:   body[:expires_in] || body[:expires_on]&.then { |t| t.to_i - Time.now.to_i },
                scopes:       'https://graph.microsoft.com/.default'
              )
            end
          end
        end
      end
    end
  end
end
