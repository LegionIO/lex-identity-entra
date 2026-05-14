# frozen_string_literal: true

require 'legion/extensions/identity/entra/helpers/scope_registry'

module Legion
  module Extensions
    module Identity
      module Entra
        module Application
          ScopeRegistry = Legion::Extensions::Identity::Entra::Helpers::ScopeRegistry.new(pattern: :application)
        end
      end
    end
  end
end
