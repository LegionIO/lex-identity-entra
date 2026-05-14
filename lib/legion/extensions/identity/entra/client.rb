# frozen_string_literal: true

require 'concurrent-ruby'
require 'faraday'
require 'legion/extensions/identity/entra/helpers/scopes'
require 'legion/extensions/identity/entra/helpers/scope_registry'
require 'legion/extensions/identity/entra/helpers/token_manager'

module Legion
  module Extensions
    module Identity
      module Entra
        class Client
          GRAPH_BASE = 'https://graph.microsoft.com/v1.0'

          @instances = Concurrent::Map.new
          @registries = Concurrent::Map.new

          class << self
            def instance(pattern: :delegated)
              @instances.compute_if_absent(pattern.to_sym) { client_class_for(pattern).new }
            end

            def graph(pattern: :delegated)
              instance(pattern: pattern).connection
            end

            def registry(pattern: :delegated)
              @registries.compute_if_absent(pattern.to_sym) do
                Legion::Extensions::Identity::Entra::Helpers::ScopeRegistry.new(pattern: pattern)
              end
            end

            def permitted?(scope, pattern: :delegated)
              registry(pattern: pattern).permitted?(scope)
            end

            def permitted_all?(*scopes, pattern: :delegated)
              registry(pattern: pattern).permitted_all?(*scopes)
            end

            def permitted_any?(*scopes, pattern: :delegated)
              registry(pattern: pattern).permitted_any?(*scopes)
            end

            def denied_scopes(pattern: :delegated)
              registry(pattern: pattern).denied
            end

            def reset!(pattern: nil)
              if pattern
                @instances.delete(pattern.to_sym)
                @registries[pattern.to_sym]&.reset!
              else
                @instances.clear
                @registries.each_value(&:reset!)
              end
            end

            def authenticated?(pattern: :delegated)
              Legion::Extensions::Identity::Entra::Helpers::TokenManager.authenticated?(pattern)
            end

            private

            def client_class_for(pattern)
              case pattern.to_sym
              when :delegated        then Delegated::Client
              when :application      then Application::Client
              when :managed_identity then ManagedIdentity::Client
              when :workload_identity then WorkloadIdentity::Client
              else self
              end
            end
          end

          def initialize
            @connection = Concurrent::AtomicReference.new(nil)
            @access_token = Concurrent::AtomicReference.new(nil)
          end

          def pattern
            raise NotImplementedError, "#{self.class} must define #pattern"
          end

          def connection
            @connection.set(nil) if token_expired?
            conn = @connection.get
            return conn if conn

            @connection.compare_and_set(nil, build_connection)
            @connection.get
          end

          def get(path, params: {})
            connection.get(path, params)
          end

          def post(path, body: {})
            connection.post(path) do |req|
              req.headers['Content-Type'] = 'application/json'
              req.body = json_dump(body)
            end
          end

          def patch(path, body: {})
            connection.patch(path) do |req|
              req.headers['Content-Type'] = 'application/json'
              req.body = json_dump(body)
            end
          end

          def delete(path)
            connection.delete(path)
          end

          def access_token
            @access_token.set(nil) if token_expired?
            token = @access_token.get
            return token if token

            resolved = resolve_token
            @access_token.compare_and_set(nil, resolved)
            @access_token.get
          end

          private

          def resolve_token
            token = Legion::Extensions::Identity::Entra::Helpers::TokenManager.load_token(pattern)
            if token
              sync_registry_from_cache
              return token
            end

            authenticate
            Legion::Extensions::Identity::Entra::Helpers::TokenManager.load_token(pattern)
          end

          def sync_registry_from_cache
            data = Legion::Extensions::Identity::Entra::Helpers::TokenManager.token_data(pattern, refresh: false)
            return unless data&.dig(:scopes)

            reg = Legion::Extensions::Identity::Entra::Client.registry(pattern: pattern)
            reg.record_requested(Legion::Extensions::Identity::Entra::Helpers::Scopes.resolve(pattern: pattern))
            reg.record_granted(data[:scopes])
          end

          def authenticate
            raise NotImplementedError, "#{self.class} must implement #authenticate"
          end

          def build_connection
            token = access_token
            Faraday.new(url: GRAPH_BASE) do |f|
              f.headers['Authorization'] = "Bearer #{token}"
              f.headers['Accept'] = 'application/json'
              f.options.open_timeout = 5
              f.options.timeout = 30
            end
          end

          def token_expired?
            data = Legion::Extensions::Identity::Entra::Helpers::TokenManager.token_data(pattern, refresh: false)
            return true unless data

            Legion::Extensions::Identity::Entra::Helpers::TokenManager.expired?(data)
          end

          def registry
            Legion::Extensions::Identity::Entra::Client.registry(pattern: pattern)
          end

          def auth_settings
            Legion::Extensions::Identity::Entra::Helpers::TokenManager.settings_auth
          end
        end
      end
    end
  end
end
