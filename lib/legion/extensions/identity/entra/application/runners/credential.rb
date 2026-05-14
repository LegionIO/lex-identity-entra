# frozen_string_literal: true

require 'faraday'
require 'legion/extensions/identity/entra/helpers/scopes'

module Legion
  module Extensions
    module Identity
      module Entra
        module Application
          module Runners
            module Credential
              include Legion::Logging::Helper
              include Legion::Settings::Helper

              DEFAULT_SCOPE = 'https://graph.microsoft.com/.default'

              def acquire_token(tenant_id:, client_id:, client_secret:,
                                scope: DEFAULT_SCOPE, **)
                log.debug("Credential.acquire_token: tenant=#{tenant_id}")
                result = credential_post(tenant_id,
                                         grant_type:    'client_credentials',
                                         client_id:     client_id,
                                         client_secret: client_secret,
                                         scope:         scope)
                log.info('Credential.acquire_token: token acquired') if result[:access_token]
                { result: result }
              rescue StandardError => e
                handle_exception(e, level: :error, operation: 'application.credential.acquire_token')
                { error: 'request_failed', description: e.message }
              end

              def acquire_token_with_certificate(tenant_id:, client_id:, client_assertion:,
                                                 scope: DEFAULT_SCOPE, **)
                log.debug("Credential.acquire_token_with_certificate: tenant=#{tenant_id}")
                result = credential_post(tenant_id,
                                         grant_type:            'client_credentials',
                                         client_id:             client_id,
                                         client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                                         client_assertion:      client_assertion,
                                         scope:                 scope)
                log.info('Credential.acquire_token_with_certificate: token acquired') if result[:access_token]
                { result: result }
              rescue StandardError => e
                handle_exception(e, level: :error, operation: 'application.credential.acquire_token_with_certificate')
                { error: 'request_failed', description: e.message }
              end

              def credential_post(tenant_id, form)
                log.debug("Credential.credential_post: tenant=#{tenant_id}")
                response = credential_connection(tenant_id).post('oauth2/v2.0/token',
                                                                 URI.encode_www_form(form.transform_keys(&:to_s)))
                body = response.body.to_s.empty? ? {} : json_load(response.body)
                unless response.success?
                  body[:error] ||= "http_#{response.status}"
                  body[:error_description] ||= response.reason_phrase
                  log.debug("Credential.credential_post: error=#{body[:error]} status=#{response.status}")
                end
                body
              end

              private

              def credential_connection(tenant_id)
                Faraday.new(url: "https://login.microsoftonline.com/#{tenant_id}/") do |f|
                  f.headers['Accept'] = 'application/json'
                  f.headers['Content-Type'] = 'application/x-www-form-urlencoded'
                  f.options.open_timeout = 5
                  f.options.timeout = 15
                end
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
