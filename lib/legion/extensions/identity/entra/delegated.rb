# frozen_string_literal: true

require_relative 'delegated/scopes'
require_relative 'delegated/scope_registry'
require_relative 'delegated/runners/login'
require_relative 'delegated/runners/on_behalf_of'
require_relative 'delegated/client'
require_relative 'delegated/identity'
require_relative 'delegated/actors/auth_validator'
require_relative 'delegated/actors/token_refresher'
require_relative 'delegated/cli/auth'
require_relative 'delegated/hooks/auth'

module Legion
  module Extensions
    module Identity
      module Entra
        module Delegated
          extend Legion::Extensions::Core if Legion::Extensions.const_defined?(:Core, false)

          def self.identity_provider? = true
          def self.remote_invocable?  = false

          def self.default_settings
            {
              logger:       { level: 'info' },
              workers:      1,
              runners:      {},
              auth:         {
                tenant_id: nil,
                client_id: nil
              },
              scopes:       {
                enabled_categories: %i[microsoft_graph azure_communication_services sharepoint yammer one_note],
                category_overrides: {}
              },
              token:        {
                vault_path:       nil,
                local_token_path: nil,
                refresh_buffer:   60,
                refresh_interval: 900
              },
              browser_auth: {
                auto_authenticate:  false,
                force_local_server: false,
                callback_timeout:   120
              }
            }
          end
        end
      end
    end
  end
end
