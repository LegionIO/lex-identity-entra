# frozen_string_literal: true

require 'faraday'

module Legion
  module Extensions
    module Identity
      module Entra
        module WorkloadIdentity
          module Runners
            module Token
              include Legion::Logging::Helper
              include Legion::Settings::Helper

              DEFAULT_SCOPE = 'https://graph.microsoft.com/.default'

              def acquire_federated_token(tenant_id:, client_id:, assertion:,
                                          scope: DEFAULT_SCOPE,
                                          assertion_file: nil, **)
                log.debug("WorkloadIdentity::Token.acquire_federated: tenant=#{tenant_id}")
                assertion = resolve_assertion(assertion, assertion_file)
                unless assertion
                  log.warn('WorkloadIdentity::Token.acquire_federated: no assertion available')
                  return { error: 'missing_assertion', description: 'No SA token or assertion file available' }
                end

                result = federation_post(tenant_id,
                                         grant_type:            'client_credentials',
                                         client_id:             client_id,
                                         client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                                         client_assertion:      assertion,
                                         scope:                 scope)
                log.info('WorkloadIdentity::Token.acquire_federated: token acquired') if result[:access_token]
                { result: result }
              rescue StandardError => e
                handle_exception(e, level: :error, operation: 'workload_identity.token.acquire_federated')
                { error: 'request_failed', description: e.message }
              end

              def acquire_from_environment(scope: DEFAULT_SCOPE, **)
                log.debug('WorkloadIdentity::Token.acquire_from_environment: reading env vars')
                tenant_id = ENV.fetch('AZURE_TENANT_ID', nil)
                client_id = ENV.fetch('AZURE_CLIENT_ID', nil)
                token_file = ENV.fetch('AZURE_FEDERATED_TOKEN_FILE', nil)

                unless tenant_id && client_id && token_file
                  log.warn('WorkloadIdentity::Token.acquire_from_environment: missing env vars')
                  return { error:       'missing_env',
                           description: 'AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_FEDERATED_TOKEN_FILE required' }
                end

                acquire_federated_token(tenant_id: tenant_id, client_id: client_id,
                                        assertion: nil, assertion_file: token_file,
                                        scope: scope)
              end

              def federation_post(tenant_id, form)
                log.debug("WorkloadIdentity::Token.federation_post: tenant=#{tenant_id}")
                response = federation_connection(tenant_id).post('oauth2/v2.0/token',
                                                                 URI.encode_www_form(form.transform_keys(&:to_s)))
                body = response.body.to_s.empty? ? {} : json_load(response.body)
                unless response.success?
                  body[:error] ||= "http_#{response.status}"
                  body[:error_description] ||= response.reason_phrase
                  log.debug("WorkloadIdentity::Token.federation_post: error=#{body[:error]} status=#{response.status}")
                end
                body
              end

              private

              def resolve_assertion(assertion, assertion_file)
                if assertion && !assertion.empty?
                  log.debug('WorkloadIdentity::Token: using provided assertion')
                  assertion
                elsif assertion_file && File.exist?(assertion_file)
                  log.debug("WorkloadIdentity::Token: reading assertion from #{assertion_file}")
                  File.read(assertion_file).strip
                end
              end

              def federation_connection(tenant_id)
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
