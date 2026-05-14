# frozen_string_literal: true

require 'legion/extensions/identity/entra/helpers/scope_registry'

module Legion
  module Extensions
    module Identity
      module Entra
        module WorkloadIdentity
          ScopeRegistry = Legion::Extensions::Identity::Entra::Helpers::ScopeRegistry.new(pattern: :workload_identity)
        end
      end
    end
  end
end
