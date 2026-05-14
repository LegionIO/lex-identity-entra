# frozen_string_literal: true

require 'concurrent-ruby'

module Legion
  module Extensions
    module Identity
      module Entra
        module Helpers
          class ScopeRegistry
            attr_reader :pattern

            def initialize(pattern:)
              @pattern = pattern.to_sym
              @requested = Concurrent::AtomicReference.new([])
              @granted = Concurrent::AtomicReference.new([])
            end

            def requested
              @requested.get.dup
            end

            def granted
              @granted.get.dup
            end

            def record_requested(scopes)
              @requested.set(normalize(scopes).uniq.freeze)
            end

            def record_granted(scopes)
              @granted.set(normalize(scopes).uniq.freeze)
            end

            def permitted?(scope)
              @granted.get.include?(scope.to_s)
            end

            def permitted_all?(*scopes)
              granted_set = @granted.get
              scopes.flatten.all? { |s| granted_set.include?(s.to_s) }
            end

            def permitted_any?(*scopes)
              granted_set = @granted.get
              scopes.flatten.any? { |s| granted_set.include?(s.to_s) }
            end

            def denied
              @requested.get - @granted.get
            end

            def reset!
              @requested.set([])
              @granted.set([])
            end

            private

            def normalize(scopes)
              case scopes
              when Array then scopes.map(&:to_s)
              when String then scopes.split.map(&:strip).reject(&:empty?)
              else []
              end
            end
          end
        end
      end
    end
  end
end
