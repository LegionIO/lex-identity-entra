# frozen_string_literal: true

require_relative 'entra/version'
require_relative 'entra/helpers/graph_client'
require_relative 'entra/helpers/token_manager'
require_relative 'entra/helpers/account_discovery'
require_relative 'entra/identity'

module Legion
  module Extensions
    module Identity
      module Entra
        extend Legion::Extensions::Core if Legion::Extensions.const_defined?(:Core, false)

        def self.identity_provider? = true
        def self.remote_invocable?  = false
      end
    end
  end
end

if defined?(Legion::Identity::Resolver)
  Legion::Identity::Resolver.register(Legion::Extensions::Identity::Entra::Identity)
elsif defined?(Legion::Identity) && Legion::Identity.respond_to?(:pending_registrations)
  Legion::Identity.pending_registrations << Legion::Extensions::Identity::Entra::Identity
end
