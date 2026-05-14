# frozen_string_literal: true

require_relative 'managed_identity/scopes'
require_relative 'managed_identity/scope_registry'
require_relative 'managed_identity/runners/token'
require_relative 'managed_identity/actors/token_refresher'
require_relative 'managed_identity/client'

module Legion
  module Extensions
    module Identity
      module Entra
        module ManagedIdentity
          extend Legion::Extensions::Core if Legion::Extensions.const_defined?(:Core, false)

          def self.identity_provider? = false
          def self.remote_invocable?  = false

          def self.default_settings
            {
              logger:    { level: 'info' },
              workers:   1,
              runners:   {},
              resource:  'https://graph.microsoft.com',
              client_id: nil,
              scopes:    {
                enabled_categories: [:microsoft_graph],
                category_overrides: {}
              },
              token:     {
                vault_path:       nil,
                local_token_path: nil,
                refresh_buffer:   60,
                refresh_interval: 2700
              }
            }
          end
        end
      end
    end
  end
end
