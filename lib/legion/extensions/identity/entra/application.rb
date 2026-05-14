# frozen_string_literal: true

require_relative 'application/scopes'
require_relative 'application/scope_registry'
require_relative 'application/runners/credential'
require_relative 'application/actors/token_refresher'
require_relative 'application/client'

module Legion
  module Extensions
    module Identity
      module Entra
        module Application
          extend Legion::Extensions::Core if Legion::Extensions.const_defined?(:Core, false)

          def self.identity_provider? = false
          def self.remote_invocable?  = false

          def self.default_settings
            {
              logger:  { level: 'info' },
              workers: 1,
              runners: {},
              auth:    {
                tenant_id:     nil,
                client_id:     nil,
                client_secret: nil,
                certificate:   nil
              },
              scopes:  {
                enabled_categories: [:microsoft_graph],
                category_overrides: {}
              },
              token:   {
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
