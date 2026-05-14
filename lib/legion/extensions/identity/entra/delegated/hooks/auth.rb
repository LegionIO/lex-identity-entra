# frozen_string_literal: true

if defined?(Legion::Extensions::Hooks::Base)
  module Legion
    module Extensions
      module Identity
        module Entra
          module Delegated
            module Hooks
              class Auth < Legion::Extensions::Hooks::Base # rubocop:disable Legion/Extension/HookMissingRunnerClass
                mount '/callback'

                def self.runner_class
                  'Legion::Extensions::Identity::Entra::Delegated::Runners::Login'
                end
              end
            end
          end
        end
      end
    end
  end
end
