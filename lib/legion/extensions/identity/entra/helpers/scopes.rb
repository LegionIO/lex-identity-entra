# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module Helpers
          module Scopes
            BASE = %w[openid profile email offline_access].freeze

            def self.resolve(pattern:, categories_hash: nil)
              cats = categories_hash || catalog_for(pattern)
              enabled = enabled_categories(pattern: pattern)
              additional = enabled.flat_map { |cat| scopes_for(pattern: pattern, category: cat, catalog: cats) }
              (BASE + additional).uniq.join(' ')
            end

            def self.scopes_for(pattern:, category:, catalog: nil)
              configured = settings_scopes_for(pattern: pattern, category: category)
              return configured if configured

              cats = catalog || catalog_for(pattern)
              cats.fetch(category, [])
            end

            def self.enabled_categories(pattern:)
              configured = setting(pattern, :enabled_categories)
              return configured.map(&:to_sym) if configured.is_a?(Array) && !configured.empty?

              [:microsoft_graph]
            end

            def self.catalog_for(pattern)
              case pattern.to_sym
              when :delegated       then Delegated::Scopes::CATEGORIES
              when :application     then Application::Scopes::CATEGORIES
              when :managed_identity  then ManagedIdentity::Scopes::CATEGORIES
              when :workload_identity then WorkloadIdentity::Scopes::CATEGORIES
              else {}
              end
            end

            def self.settings_scopes_for(pattern:, category:)
              overrides = setting(pattern, :category_overrides)
              return nil unless overrides.is_a?(Hash)

              val = overrides[category] || overrides[category.to_s]
              val.is_a?(Array) && !val.empty? ? val.map(&:to_s) : nil
            end

            def self.setting(pattern, key)
              return nil unless defined?(Legion::Settings)

              Legion::Settings.dig(:identity, :entra, pattern.to_sym, :scopes, key)
            end
          end
        end
      end
    end
  end
end
