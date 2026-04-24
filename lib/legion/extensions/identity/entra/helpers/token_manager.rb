# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'

module Legion
  module Extensions
    module Identity
      module Entra
        module Helpers
          module TokenManager
            TOKEN_DIR = File.join(Dir.home, '.legionio', 'tokens')

            module_function

            def load_token(qualifier = :delegated)
              from_vault(qualifier) || from_local_file(qualifier)
            end

            def save_token(qualifier, access_token:, refresh_token: nil, expires_at: nil)
              save_to_vault(qualifier, access_token: access_token, refresh_token: refresh_token,
                                       expires_at: expires_at)
              save_to_local(qualifier, access_token: access_token, refresh_token: refresh_token,
                                       expires_at: expires_at)
            end

            def from_vault(qualifier)
              return nil unless vault_available?

              path = vault_path(qualifier)
              data = Legion::Crypt.vault_read(path)
              return nil unless data.is_a?(Hash) && data[:access_token]

              data[:access_token]
            rescue StandardError => _e
              nil
            end

            def from_local_file(qualifier)
              path = local_path(qualifier)
              return nil unless File.exist?(path)

              data = ::JSON.parse(File.read(path))
              return nil unless data['access_token']

              return nil if data['expires_at'] && (Time.parse(data['expires_at']) <= Time.now)

              data['access_token']
            rescue StandardError => _e
              nil
            end

            def save_to_vault(qualifier, access_token:, refresh_token:, expires_at:)
              return unless vault_available?

              path = vault_path(qualifier)
              Legion::Crypt.vault_write(path, access_token:  access_token,
                                              refresh_token: refresh_token,
                                              expires_at:    expires_at&.utc&.iso8601)
            rescue StandardError => _e
              nil
            end

            def save_to_local(qualifier, access_token:, refresh_token:, expires_at:)
              path = local_path(qualifier)
              FileUtils.mkdir_p(File.dirname(path))
              File.write(path, ::JSON.pretty_generate(
                                 'access_token'  => access_token,
                                 'refresh_token' => refresh_token,
                                 'expires_at'    => expires_at&.utc&.iso8601
                               ))
              File.chmod(0o600, path)
            rescue StandardError => _e
              nil
            end

            def vault_available?
              defined?(Legion::Crypt) &&
                Legion::Crypt.respond_to?(:vault_connected?) &&
                Legion::Crypt.vault_connected?
            end

            def vault_path(qualifier)
              identity = if defined?(Legion::Identity::Process) && Legion::Identity::Process.resolved?
                           Legion::Identity::Process.canonical_name
                         else
                           'default'
                         end
              "users/#{identity}/entra_#{qualifier}"
            end

            def local_path(qualifier)
              File.join(TOKEN_DIR, "entra_#{qualifier}.json")
            end
          end
        end
      end
    end
  end
end
