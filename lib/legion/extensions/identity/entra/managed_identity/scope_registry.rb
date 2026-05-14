# frozen_string_literal: true

require 'legion/extensions/identity/entra/helpers/scope_registry'

module Legion
  module Extensions
    module Identity
      module Entra
        module ManagedIdentity
          ScopeRegistry = Legion::Extensions::Identity::Entra::Helpers::ScopeRegistry.new(pattern: :managed_identity)
        end
      end
    end
  end
end
