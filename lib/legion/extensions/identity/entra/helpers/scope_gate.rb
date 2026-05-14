# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module Helpers
          module ScopeGate
            def self.included(base)
              base.extend(ClassMethods)
            end

            module ClassMethods
              def scope_pattern
                @scope_pattern || :delegated
              end

              def uses_pattern(pattern)
                @scope_pattern = pattern.to_sym
              end

              def required_scopes
                @required_scopes ||= {}
              end

              def requires_scope(method_name, *scopes, all: true)
                required_scopes[method_name.to_sym] = { scopes: scopes.flatten, all: all }
              end

              def available_methods
                required_scopes.select { |_, req| scope_satisfied?(req) }.keys
              end

              def unavailable_methods
                required_scopes.reject { |_, req| scope_satisfied?(req) }.keys
              end

              def method_permitted?(method_name)
                req = required_scopes[method_name.to_sym]
                return true unless req

                scope_satisfied?(req)
              end

              def scope_requirements
                required_scopes.transform_values do |req|
                  { scopes: req[:scopes], permitted: scope_satisfied?(req) }
                end
              end

              private

              def scope_satisfied?(req)
                reg = Client.registry(pattern: scope_pattern)
                if req[:all]
                  reg.permitted_all?(req[:scopes])
                else
                  reg.permitted_any?(req[:scopes])
                end
              end
            end

            private

            def check_scope!(method_name = nil)
              owner = scope_gate_owner
              return true unless owner

              req = owner.required_scopes[method_name]
              return true unless req

              reg = Client.registry(pattern: owner.scope_pattern)
              permitted = if req[:all]
                            reg.permitted_all?(req[:scopes])
                          else
                            reg.permitted_any?(req[:scopes])
                          end

              return true if permitted

              { error: 'insufficient_scope', required: req[:scopes], granted: reg.granted }
            end

            def scope_gate_owner
              if self.class.respond_to?(:required_scopes)
                self.class
              else
                (singleton_class.ancestors + self.class.ancestors).find { |m| m.respond_to?(:required_scopes) }
              end
            end
          end
        end
      end
    end
  end
end
