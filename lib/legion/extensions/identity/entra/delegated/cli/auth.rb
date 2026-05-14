# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module Delegated
          module CLI
            class Auth
              def self.cli_alias = 'entra'

              def self.descriptions
                {
                  login:  'Authenticate with Microsoft Entra via delegated OAuth',
                  status: 'Show current Entra authentication state'
                }
              end

              def login(tenant_id: nil, client_id: nil, scopes: nil, **)
                settings = tenant_id && client_id ? {} : resolve_settings
                tid = tenant_id || settings[:tenant_id] || ENV.fetch('AZURE_TENANT_ID', nil)
                cid = client_id || settings[:client_id] || ENV.fetch('AZURE_CLIENT_ID', nil)
                requested_scopes = scopes || settings.dig(:delegated, :scopes) || Helpers::BrowserAuth.default_scopes

                unless tid && cid
                  puts 'Error: tenant_id and client_id required (set identity.entra.auth, env vars, or pass as args)'
                  return { error: 'missing_config' }
                end

                browser_auth = Helpers::BrowserAuth.new(tenant_id: tid, client_id: cid,
                                                        scopes: requested_scopes, force_local_server: true)
                result = browser_auth.authenticate
                body = result&.dig(:result)

                if body&.dig(:access_token)
                  store_token(body, tenant_id: tid, client_id: cid, scopes: requested_scopes)
                  puts 'Entra authenticated successfully.'
                else
                  puts 'Entra authentication failed or was cancelled.'
                end

                result
              rescue StandardError => e
                puts "Error: #{e.message}"
                { error: 'login_failed', description: e.message }
              end

              def status
                data = Helpers::TokenManager.token_data(:delegated, refresh: false)
                if data && !Helpers::TokenManager.expired?(data)
                  puts 'Entra: authenticated (delegated token present)'
                  { result: { authenticated: true, expires_at: data[:expires_at]&.utc&.iso8601 } }
                else
                  puts 'Entra: not authenticated'
                  { result: { authenticated: false } }
                end
              end

              private

              def resolve_settings
                Helpers::TokenManager.settings_auth
              end

              def store_token(body, tenant_id:, client_id:, scopes:)
                Helpers::TokenManager.save_token(
                  :delegated,
                  access_token:  body[:access_token],
                  refresh_token: body[:refresh_token],
                  expires_in:    body[:expires_in],
                  scopes:        body[:scope] || scopes,
                  tenant_id:     tenant_id,
                  client_id:     client_id
                )
              end
            end
          end
        end
      end
    end
  end
end
