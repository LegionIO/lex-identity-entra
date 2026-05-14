# frozen_string_literal: true

require 'digest'
require 'rbconfig'
require 'securerandom'
require 'faraday'

require 'legion/extensions/identity/entra/helpers/callback_server'
require 'legion/extensions/identity/entra/delegated/runners/login'

module Legion
  module Extensions
    module Identity
      module Entra
        module Helpers
          class BrowserAuth
            include Legion::Logging::Helper
            include Legion::Settings::Helper

            def self.default_scopes
              Legion::Extensions::Identity::Entra::Helpers::Scopes.resolve(pattern: :delegated)
            end

            attr_reader :tenant_id, :client_id, :scopes

            def initialize(tenant_id:, client_id:, scopes: self.class.default_scopes, auth: nil, force_local_server: false, **)
              @tenant_id = tenant_id
              @client_id = client_id
              @scopes = scopes
              @auth = auth || Object.new.extend(Legion::Extensions::Identity::Entra::Delegated::Runners::Login)
              @force_local_server = force_local_server
              log.debug("BrowserAuth initialized: tenant=#{tenant_id} client=#{client_id} force_local=#{force_local_server}")
              log.info("BrowserAuth scopes: #{@scopes}")
            end

            def authenticate
              if gui_available?
                log.info('BrowserAuth: GUI available, using browser auth')
                authenticate_browser
              else
                log.info('BrowserAuth: no GUI detected, using device code flow')
                authenticate_device_code
              end
            end

            def api_hook_available?
              return false if @force_local_server
              return false unless defined?(Legion::API) && defined?(Legion::Events)
              return false unless defined?(Legion::Extensions::Hooks::Base)

              hook_route_registered?
            end

            def hook_redirect_uri
              port = Legion::Settings.dig(:api, :port) || 4567
              "http://127.0.0.1:#{port}/api/extensions/identity/entra/hooks/auth/handle"
            end

            def generate_pkce
              verifier = SecureRandom.hex(32)
              challenge = [Digest::SHA256.digest(verifier)].pack('m0').tr('+/', '-_').delete('=')
              log.debug('BrowserAuth: PKCE challenge generated')
              [verifier, challenge]
            end

            def gui_available?
              os = host_os
              return true if /darwin|mswin|mingw/.match?(os)

              !ENV['DISPLAY'].nil? || !ENV['WAYLAND_DISPLAY'].nil?
            end

            def open_browser(url)
              cmd = case host_os
                    when /darwin/ then 'open'
                    when /linux/ then 'xdg-open'
                    when /mswin|mingw/ then 'start'
                    end
              unless cmd
                log.warn('BrowserAuth: no browser command found for this OS')
                return false
              end

              log.debug("BrowserAuth: opening browser with #{cmd}")
              system(cmd, url)
            end

            private

            def host_os
              RbConfig::CONFIG['host_os']
            end

            def hook_route_registered?
              log.debug("BrowserAuth: probing hook route at #{hook_redirect_uri}")
              response = Faraday.head(hook_redirect_uri) do |req|
                req.options.open_timeout = 2
                req.options.timeout = 2
              end
              registered = response.status != 404
              log.debug("BrowserAuth: hook route probe returned #{response.status} (registered=#{registered})")
              registered
            rescue StandardError => e
              handle_exception(e, level: :warn, operation: 'browser_auth.hook_route_registered?')
              false
            end

            def authenticate_browser
              verifier, challenge = generate_pkce
              state = SecureRandom.hex(32)

              if api_hook_available?
                log.info('BrowserAuth: using API hook for OAuth callback')
                authenticate_via_hook(verifier: verifier, challenge: challenge, state: state)
              else
                log.info('BrowserAuth: using local callback server')
                authenticate_via_server(verifier: verifier, challenge: challenge, state: state)
              end
            end

            def authenticate_via_hook(verifier:, challenge:, state:)
              callback_uri = hook_redirect_uri
              log.debug("BrowserAuth: hook callback URI: #{callback_uri}")
              result_holder = { result: nil }
              mutex = Mutex.new
              cv = ConditionVariable.new

              listener = Legion::Events.once('identity.entra.oauth.callback') do |event|
                log.debug('BrowserAuth: OAuth callback event received')
                mutex.synchronize do
                  result_holder[:result] = event
                  cv.broadcast
                end
              end

              url = @auth.authorize_url(tenant_id: tenant_id, client_id: client_id,
                                        redirect_uri: callback_uri, scope: scopes,
                                        state: state, code_challenge: challenge)

              unless open_browser(url)
                Legion::Events.off('identity.entra.oauth.callback', listener)
                log.warn('BrowserAuth: could not open browser, falling back to device code')
                return authenticate_device_code
              end

              log.debug('BrowserAuth: waiting for callback (timeout=120s)')
              mutex.synchronize { cv.wait(mutex, 120) unless result_holder[:result] }
              exchange_callback(result_holder[:result], state: state, verifier: verifier, callback_uri: callback_uri)
            end

            def authenticate_via_server(verifier:, challenge:, state:)
              server = CallbackServer.new
              server.start
              callback_uri = server.redirect_uri
              log.info("BrowserAuth: local server started on #{callback_uri}")

              url = @auth.authorize_url(tenant_id: tenant_id, client_id: client_id,
                                        redirect_uri: callback_uri, scope: scopes,
                                        state: state, code_challenge: challenge)

              unless open_browser(url)
                log.warn('BrowserAuth: could not open browser, falling back to device code')
                return authenticate_device_code
              end

              log.debug('BrowserAuth: waiting for callback on local server (timeout=120s)')
              result = server.wait_for_callback(timeout: 120)
              exchange_callback(result, state: state, verifier: verifier, callback_uri: callback_uri)
            ensure
              server&.shutdown
              log.debug('BrowserAuth: local callback server shut down')
            end

            def exchange_callback(result, state:, verifier:, callback_uri:)
              unless result && result[:code]
                log.error('BrowserAuth: OAuth callback timed out or missing code')
                return { error: 'timeout', description: 'No callback received within timeout' }
              end

              unless result[:state] == state
                log.error('BrowserAuth: OAuth state mismatch (possible CSRF)')
                return { error: 'state_mismatch', description: 'CSRF state parameter mismatch' }
              end

              log.info('BrowserAuth: exchanging authorization code for tokens')
              @auth.exchange_code(tenant_id: tenant_id, client_id: client_id,
                                  code: result[:code], redirect_uri: callback_uri,
                                  code_verifier: verifier, scope: scopes)
            end

            def authenticate_device_code
              log.info('BrowserAuth: starting device code flow')
              dc = @auth.request_device_code(tenant_id: tenant_id, client_id: client_id, scope: scopes)
              if dc[:error]
                log.error("BrowserAuth: device code request failed: #{dc[:error]} - #{dc[:description]}")
                return { error: dc[:error], description: dc[:description] }
              end

              body = dc[:result]
              log.info("BrowserAuth: device code flow — go to #{body[:verification_uri]} and enter code #{body[:user_code]}")
              open_browser(body[:verification_uri]) if gui_available? && body[:verification_uri]

              log.debug('BrowserAuth: polling for device code authorization')
              @auth.poll_device_code(tenant_id: tenant_id, client_id: client_id,
                                     device_code: body[:device_code])
            end
          end
        end
      end
    end
  end
end
