# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'time'

module Legion
  module Extensions
    module Identity
      module Entra
        module Helpers
          module TokenManager
            extend self
            include Legion::Logging::Helper
            include Legion::Settings::Helper
            include Legion::JSON::Helper

            TOKEN_DIR = File.join(Dir.home, '.legionio', 'tokens')
            REFRESH_BUFFER = 60

            @memory_store = {}.freeze

            def self.memory_store
              @memory_store
            end

            def load_token(qualifier = :delegated)
              log.debug("TokenManager.load_token: qualifier=#{qualifier}")
              data = token_data(qualifier, refresh: true)
              token = data&.dig(:access_token) || from_broker(qualifier)
              log.debug("TokenManager.load_token: #{token ? 'token found' : 'no token available'}")
              token
            end

            def token_data(qualifier = :delegated, refresh: true)
              log.debug("TokenManager.token_data: qualifier=#{qualifier} refresh=#{refresh}")
              vault_data = from_vault_data(qualifier)
              other_data = vault_data || from_local_data(qualifier) || from_memory(qualifier)
              if other_data && !vault_data && vault_available? && trusted_process_identity?
                log.info("TokenManager.token_data: backfilling #{qualifier} token to vault")
                backfill_saved = save_to_vault(qualifier, access_token:      other_data[:access_token],
                                                          refresh_token:     other_data[:refresh_token],
                                                          expires_at:        other_data[:expires_at],
                                                          scopes:            other_data[:scopes],
                                                          tenant_id:         other_data[:tenant_id],
                                                          client_id:         other_data[:client_id],
                                                          scope_fingerprint: other_data[:scope_fingerprint])
                delete_local(qualifier) if backfill_saved
              end
              data = other_data
              return nil unless data

              if scope_fingerprint_stale?(qualifier, data)
                log.info("TokenManager.token_data: scope fingerprint mismatch for #{qualifier}, forcing re-auth")
                return nil
              end

              return data unless expired?(data)

              log.debug("TokenManager.token_data: token expired for #{qualifier}")
              refresh ? refresh_token(qualifier, data) : data
            end

            def save_token(qualifier, access_token:, refresh_token: nil, expires_at: nil,
                           expires_in: nil, scopes: nil, tenant_id: nil, client_id: nil)
              log.debug("TokenManager.save_token: qualifier=#{qualifier} expires_in=#{expires_in}")
              expires_at ||= Time.now + expires_in.to_i if expires_in
              fingerprint = current_scope_fingerprint(qualifier)
              vault_saved = save_to_vault(qualifier, access_token: access_token, refresh_token: refresh_token,
                                                     expires_at: expires_at, scopes: scopes,
                                                     tenant_id: tenant_id, client_id: client_id,
                                                     scope_fingerprint: fingerprint)
              if vault_saved
                delete_local(qualifier)
              else
                save_to_local(qualifier, access_token: access_token, refresh_token: refresh_token,
                                         expires_at: expires_at, scopes: scopes,
                                         tenant_id: tenant_id, client_id: client_id,
                                         scope_fingerprint: fingerprint)
              end
              save_to_memory(qualifier, access_token: access_token, refresh_token: refresh_token,
                                        expires_at: expires_at, scopes: scopes,
                                        tenant_id: tenant_id, client_id: client_id,
                                        scope_fingerprint: fingerprint)
            end

            def from_vault_data(qualifier)
              return nil unless vault_available? && trusted_process_identity?

              path = vault_path(qualifier)
              log.debug("TokenManager.from_vault_data: reading kv/#{path}")
              result = vault_kv_client.read(path)
              normalize_token_data(result&.data)
            rescue StandardError => e
              handle_exception(e, level: :warn, operation: 'token_manager.from_vault_data',
                                  qualifier: qualifier)
              nil
            end

            def from_local_data(qualifier)
              path = local_path(qualifier)
              return nil unless File.exist?(path)

              log.debug("TokenManager.from_local_data: reading #{path}")
              normalize_token_data(json_load(File.read(path)))
            rescue StandardError => e
              handle_exception(e, level: :warn, operation: 'token_manager.from_local_data',
                                  qualifier: qualifier, path: path)
              nil
            end

            def save_to_vault(qualifier, access_token:, refresh_token:, expires_at:,
                              scopes: nil, tenant_id: nil, client_id: nil, scope_fingerprint: nil)
              return unless vault_available?

              path = vault_path(qualifier)
              cluster = Legion::Crypt.respond_to?(:default_cluster_name) ? Legion::Crypt.default_cluster_name : 'vault'
              log.info("TokenManager.save_to_vault: writing to #{cluster} :: kv/data/#{path} qualifier=#{qualifier}")
              vault_kv_client.write(path,
                                    access_token:      access_token,
                                    refresh_token:     refresh_token,
                                    expires_at:        expires_at&.utc&.iso8601,
                                    scopes:            scopes,
                                    tenant_id:         tenant_id,
                                    client_id:         client_id,
                                    scope_fingerprint: scope_fingerprint)
              log.info('TokenManager.save_to_vault: success')
              true
            rescue StandardError => e
              handle_exception(e, level: :warn, operation: 'token_manager.save_to_vault',
                                  qualifier: qualifier)
              nil
            end

            def save_to_local(qualifier, access_token:, refresh_token:, expires_at:,
                              scopes: nil, tenant_id: nil, client_id: nil, scope_fingerprint: nil)
              path = local_path(qualifier)
              log.debug("TokenManager.save_to_local: writing #{path}")
              FileUtils.mkdir_p(File.dirname(path))
              File.write(path, json_dump({
                                           access_token:      access_token,
                                           refresh_token:     refresh_token,
                                           expires_at:        expires_at&.utc&.iso8601,
                                           scopes:            scopes,
                                           tenant_id:         tenant_id,
                                           client_id:         client_id,
                                           scope_fingerprint: scope_fingerprint
                                         }))
              File.chmod(0o600, path)
              log.debug('TokenManager.save_to_local: success')
            rescue StandardError => e
              handle_exception(e, level: :warn, operation: 'token_manager.save_to_local',
                                  qualifier: qualifier, path: path)
              nil
            end

            def delete_local(qualifier)
              path = local_path(qualifier)
              return unless File.exist?(path)

              File.delete(path)
              log.info("TokenManager.delete_local: removed #{path} (vault is authoritative)")
            rescue StandardError => e
              handle_exception(e, level: :warn, operation: 'token_manager.delete_local', qualifier: qualifier)
            end

            def from_memory(qualifier)
              data = TokenManager.memory_store[qualifier.to_sym]
              return nil unless data

              log.debug("TokenManager.from_memory: token found for #{qualifier}")
              normalize_token_data(data)
            end

            def save_to_memory(qualifier, access_token:, refresh_token:, expires_at:,
                               scopes: nil, tenant_id: nil, client_id: nil, scope_fingerprint: nil)
              TokenManager.memory_store[qualifier.to_sym] = {
                access_token:      access_token,
                refresh_token:     refresh_token,
                expires_at:        expires_at&.utc&.iso8601,
                scopes:            scopes,
                tenant_id:         tenant_id,
                client_id:         client_id,
                scope_fingerprint: scope_fingerprint
              }
              log.debug("TokenManager.save_to_memory: stored token for #{qualifier}")
            end

            def current_scope_fingerprint(qualifier)
              scopes = Helpers::Scopes.resolve(pattern: qualifier.to_sym)
              Digest::MD5.hexdigest(scopes.split.sort.join(' '))
            end

            def scope_fingerprint_stale?(qualifier, data = nil)
              data ||= from_local_data(qualifier) || from_memory(qualifier)
              return false unless data

              stored = data[:scope_fingerprint]
              return true unless stored

              stored != current_scope_fingerprint(qualifier)
            end

            def refresh_token(qualifier, data)
              log.debug("TokenManager.refresh_token: attempting refresh for #{qualifier}")
              refresh = data[:refresh_token]
              unless refresh
                log.debug('TokenManager.refresh_token: no refresh_token available')
                return nil
              end

              auth = settings_auth.merge(data.compact)
              unless auth[:tenant_id] && auth[:client_id]
                log.debug('TokenManager.refresh_token: missing tenant_id or client_id')
                return nil
              end

              runner = Object.new.extend(Legion::Extensions::Identity::Entra::Delegated::Runners::Login)
              result = runner.refresh_delegated_token(
                tenant_id:     auth[:tenant_id],
                client_id:     auth[:client_id],
                refresh_token: refresh,
                scope:         auth[:scopes] || Legion::Extensions::Identity::Entra::Helpers::Scopes.resolve(pattern: :delegated)
              )
              body = result[:result]
              access_token = fetch_key(body, :access_token)
              unless access_token
                log.warn("TokenManager.refresh_token: refresh failed for #{qualifier}, no access_token in response")
                return nil
              end

              log.info("TokenManager.refresh_token: successfully refreshed token for #{qualifier}")
              save_token(qualifier,
                         access_token:  access_token,
                         refresh_token: fetch_key(body, :refresh_token) || refresh,
                         expires_in:    fetch_key(body, :expires_in) || 3600,
                         scopes:        fetch_key(body, :scope) || auth[:scopes],
                         tenant_id:     auth[:tenant_id],
                         client_id:     auth[:client_id])
              from_local_data(qualifier)
            rescue StandardError => e
              handle_exception(e, level: :error, operation: 'token_manager.refresh_token',
                                  qualifier: qualifier)
              nil
            end

            def from_broker(qualifier)
              return nil unless defined?(Legion::Identity::Broker)

              log.debug("TokenManager.from_broker: requesting token for #{qualifier}")
              token = Legion::Identity::Broker.token_for(:entra, qualifier: qualifier)
              log.debug("TokenManager.from_broker: #{token ? 'received' : 'not available'}")
              token
            rescue StandardError => e
              handle_exception(e, level: :warn, operation: 'token_manager.from_broker',
                                  qualifier: qualifier)
              nil
            end

            def expired?(data)
              expires_at = data[:expires_at]
              return false unless expires_at

              expires_at <= (Time.now + REFRESH_BUFFER)
            end

            def authenticated?(qualifier = :delegated)
              !load_token(qualifier).nil?
            end

            def vault_available?
              defined?(Legion::Crypt) &&
                Legion::Crypt.respond_to?(:vault_connected?) &&
                Legion::Crypt.vault_connected? &&
                Legion::Crypt.respond_to?(:write)
            end

            def vault_path(qualifier)
              auth = settings_auth
              pattern_settings = auth[qualifier.to_sym]
              return pattern_settings[:vault_path] if pattern_settings.is_a?(Hash) && pattern_settings[:vault_path]

              identity = if trusted_process_identity?
                           Legion::Identity::Process.canonical_name
                         else
                           'default'
                         end
              "users/#{identity}/entra/#{qualifier}/auth"
            end

            def local_path(qualifier)
              auth = settings_auth
              pattern_settings = auth[qualifier.to_sym]
              return File.expand_path(pattern_settings[:local_token_path]) if pattern_settings.is_a?(Hash) && pattern_settings[:local_token_path]

              File.join(TOKEN_DIR, "entra_#{qualifier}.json")
            end

            def settings_auth
              identity_entra = Legion::Settings.dig(:identity, :entra) || {}
              auth = identity_entra[:auth].is_a?(Hash) ? identity_entra[:auth].dup : identity_entra.dup

              auth[:tenant_id] ||= ENV.fetch('AZURE_TENANT_ID', nil)
              auth[:client_id] ||= ENV.fetch('AZURE_CLIENT_ID', nil)
              auth[:client_secret] ||= ENV.fetch('AZURE_CLIENT_SECRET', nil)
              auth
            rescue StandardError => e
              handle_exception(e, level: :warn, operation: 'token_manager.settings_auth')
              {}
            end

            def normalize_token_data(data)
              return nil unless data.is_a?(Hash)

              access_token = fetch_key(data, :access_token)
              return nil unless access_token

              {
                access_token:      access_token,
                refresh_token:     fetch_key(data, :refresh_token),
                expires_at:        parse_time(fetch_key(data, :expires_at)),
                scopes:            fetch_key(data, :scopes) || fetch_key(data, :scope),
                tenant_id:         fetch_key(data, :tenant_id),
                client_id:         fetch_key(data, :client_id),
                scope_fingerprint: fetch_key(data, :scope_fingerprint)
              }.compact
            end

            def fetch_key(data, key)
              data[key] || data[key.to_s]
            end

            def parse_time(value)
              return value if value.is_a?(Time)
              return nil if value.nil? || value.to_s.empty?

              Time.parse(value.to_s)
            end

            def vault_kv_client
              if Legion::Crypt.respond_to?(:connected_clusters) && Legion::Crypt.connected_clusters.any?
                Legion::Crypt.send(:connected_vault_client, nil).kv('kv')
              else
                ::Vault.kv('kv')
              end
            end

            def trusted_process_identity?
              return false unless defined?(Legion::Identity::Process)
              return false unless Legion::Identity::Process.respond_to?(:resolved?) &&
                                  Legion::Identity::Process.resolved?

              return true unless Legion::Identity::Process.respond_to?(:trust)

              %i[configured verified authenticated].include?(Legion::Identity::Process.trust)
            end
          end
        end
      end
    end
  end
end
