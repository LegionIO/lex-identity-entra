# frozen_string_literal: true

require 'faraday'
require 'legion/extensions/identity/entra/helpers/scopes'
require 'legion/extensions/identity/entra/helpers/callback_page'

module Legion
  module Extensions
    module Identity
      module Entra
        module Delegated
          module Runners
            module Login
              include Legion::Logging::Helper
              include Legion::Settings::Helper

              def self.delegated_scopes
                Legion::Extensions::Identity::Entra::Helpers::Scopes.resolve(pattern: :delegated)
              end

              def request_device_code(tenant_id:, client_id:, scope: Login.delegated_scopes, **)
                log.debug("Login.request_device_code: tenant=#{tenant_id}")
                { result: oauth_post(tenant_id, 'oauth2/v2.0/devicecode',
                                     client_id: client_id,
                                     scope:     scope) }
              rescue StandardError => e
                handle_exception(e, level: :error, operation: 'delegated.login.request_device_code')
                { error: 'request_failed', description: e.message }
              end

              def poll_device_code(tenant_id:, client_id:, device_code:, interval: 5, timeout: 300, **)
                log.debug("Login.poll_device_code: tenant=#{tenant_id} timeout=#{timeout}")
                deadline = Time.now + timeout
                current_interval = interval

                while Time.now <= deadline
                  body = oauth_post(tenant_id, 'oauth2/v2.0/token',
                                    grant_type:  'urn:ietf:params:oauth:grant-type:device_code',
                                    client_id:   client_id,
                                    device_code: device_code)
                  if body[:access_token]
                    log.info('Login.poll_device_code: token acquired')
                    return { result: body }
                  end

                  case body[:error]
                  when 'authorization_pending'
                    sleep(current_interval)
                  when 'slow_down'
                    current_interval += 5
                    sleep(current_interval)
                  else
                    log.warn("Login.poll_device_code: error=#{body[:error]}")
                    return { error: body[:error], description: body[:error_description] }
                  end
                end

                log.warn("Login.poll_device_code: timed out after #{timeout}s")
                { error: 'timeout', description: "Device code flow timed out after #{timeout}s" }
              rescue StandardError => e
                handle_exception(e, level: :error, operation: 'delegated.login.poll_device_code')
                { error: 'request_failed', description: e.message }
              end

              def authorize_url(tenant_id:, client_id:, redirect_uri:, scope:, state:,
                                code_challenge:, code_challenge_method: 'S256', **)
                log.debug("Login.authorize_url: tenant=#{tenant_id}")
                params = URI.encode_www_form(
                  client_id:             client_id,
                  response_type:         'code',
                  redirect_uri:          redirect_uri,
                  scope:                 scope,
                  state:                 state,
                  code_challenge:        code_challenge,
                  code_challenge_method: code_challenge_method
                )
                "https://login.microsoftonline.com/#{tenant_id}/oauth2/v2.0/authorize?#{params}"
              end

              def exchange_code(tenant_id:, client_id:, code:, redirect_uri:, code_verifier:,
                                scope: Login.delegated_scopes, **)
                log.debug("Login.exchange_code: tenant=#{tenant_id}")
                result = oauth_post(tenant_id, 'oauth2/v2.0/token',
                                    grant_type:    'authorization_code',
                                    client_id:     client_id,
                                    code:          code,
                                    redirect_uri:  redirect_uri,
                                    code_verifier: code_verifier,
                                    scope:         scope)
                log.info('Login.exchange_code: code exchanged successfully') if result[:access_token]
                { result: result }
              rescue StandardError => e
                handle_exception(e, level: :error, operation: 'delegated.login.exchange_code')
                { error: 'request_failed', description: e.message }
              end

              def refresh_delegated_token(tenant_id:, client_id:, refresh_token:,
                                          scope: Login.delegated_scopes, **)
                log.debug("Login.refresh_delegated_token: tenant=#{tenant_id}")
                result = oauth_post(tenant_id, 'oauth2/v2.0/token',
                                    grant_type:    'refresh_token',
                                    client_id:     client_id,
                                    refresh_token: refresh_token,
                                    scope:         scope)
                log.info('Login.refresh_delegated_token: token refreshed') if result[:access_token]
                { result: result }
              rescue StandardError => e
                handle_exception(e, level: :error, operation: 'delegated.login.refresh_delegated_token')
                { error: 'request_failed', description: e.message }
              end

              def auth_callback(code: nil, state: nil, error: nil, error_description: nil, **)
                if error
                  log.warn("Login.auth_callback: provider returned error=#{error}")
                  emit_oauth_callback(state: state, error: error, error_description: error_description)
                  return { result:   { error: error },
                           response: callback_response(400, callback_failure_html(error, error_description)) }
                end

                unless code && state
                  log.warn('Login.auth_callback: missing code or state parameter')
                  return { result:   { error: 'missing_params' },
                           response: callback_response(400, callback_failure_html('missing_params',
                                                                                  'The sign-in response was missing the code or state parameter.')) }
                end

                log.info('Login.auth_callback: OAuth callback received')
                emit_oauth_callback(code: code, state: state)
                { result:   { authenticated: true, code: code, state: state },
                  response: callback_response(200, callback_success_html) }
              end
              alias handle auth_callback

              def oauth_post(tenant_id, path, form)
                log.debug("Login.oauth_post: #{path}")
                response = oauth_connection(tenant_id).post(path, URI.encode_www_form(form.transform_keys(&:to_s)))
                parse_oauth_response(response)
              end

              private

              def oauth_connection(tenant_id)
                Faraday.new(url: "https://login.microsoftonline.com/#{tenant_id}/") do |f|
                  f.headers['Accept'] = 'application/json'
                  f.headers['Content-Type'] = 'application/x-www-form-urlencoded'
                  f.options.open_timeout = 5
                  f.options.timeout = 15
                end
              end

              def parse_oauth_response(response)
                body = response.body.to_s.empty? ? {} : json_load(response.body)
                unless response.success?
                  body[:error] ||= "http_#{response.status}"
                  body[:error_description] ||= response.reason_phrase
                  log.debug("Login.parse_oauth_response: error=#{body[:error]} status=#{response.status}")
                end
                body
              end

              def emit_oauth_callback(**payload)
                return unless defined?(Legion::Events)

                Legion::Events.emit('identity.entra.oauth.callback', **payload.compact)
              end

              def callback_response(status, body)
                { status: status, content_type: 'text/html; charset=utf-8', body: body }
              end

              def callback_failure_html(error, description)
                Legion::Extensions::Identity::Entra::Helpers::CallbackPage.failure_html(error, description)
              end

              def callback_success_html
                Legion::Extensions::Identity::Entra::Helpers::CallbackPage.success_html
              end

              include Legion::Extensions::Helpers::Lex if Legion::Extensions.const_defined?(:Helpers, false) &&
                                                          Legion::Extensions::Helpers.const_defined?(:Lex, false)
            end
          end
        end
      end
    end
  end
end
