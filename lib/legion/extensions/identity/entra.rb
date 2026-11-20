# frozen_string_literal: true

require 'legion/logging'
require 'legion/logging/helper'
require 'legion/settings'
require 'legion/settings/helper'
require 'legion/json'

require_relative 'entra/version'

# Shared helpers
require_relative 'entra/helpers/scopes'
require_relative 'entra/helpers/scope_registry'
require_relative 'entra/helpers/scope_gate'
require_relative 'entra/helpers/interactive_auth_guard'
require_relative 'entra/helpers/callback_page'
require_relative 'entra/helpers/token_manager'
require_relative 'entra/helpers/graph_client'
require_relative 'entra/helpers/account_discovery'
require_relative 'entra/helpers/callback_server'
require_relative 'entra/helpers/browser_auth'

# Shared client
require_relative 'entra/client'

# Nested extensions
require_relative 'entra/delegated'
require_relative 'entra/application'
require_relative 'entra/managed_identity'
require_relative 'entra/workload_identity'

module Legion
  module Extensions
    module Identity
      module Entra
        extend Legion::Extensions::Core if Legion::Extensions.const_defined?(:Core, false)

        def self.identity_provider? = false
        def self.remote_invocable?   = false
        def self.transport_required? = false
        def self.mcp_tools?          = false
        def self.mcp_tools_deferred? = false
        def self.sticky_tools?       = false

        def self.default_settings
          { token: { restart_cache_enabled: true, restart_cache_ttl: nil } }
        end
      end
    end
  end
end

# Identity resolution can run during preload, before Core calls autobuild.
Legion::Settings.merge_settings(:extensions, { identity: { entra: Legion::Extensions::Identity::Entra.default_settings } })

if defined?(Legion::Identity::Resolver)
  Legion::Identity::Resolver.register(Legion::Extensions::Identity::Entra::Delegated::Identity)
elsif defined?(Legion::Identity) && Legion::Identity.respond_to?(:pending_registrations)
  Legion::Identity.pending_registrations << Legion::Extensions::Identity::Entra::Delegated::Identity
end
