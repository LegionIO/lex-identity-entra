# frozen_string_literal: true

require 'faraday'

module Legion
  module Extensions
    module Identity
      module Entra
        module ManagedIdentity
          module Runners
            module Token
              include Legion::Logging::Helper
              include Legion::Settings::Helper

              IMDS_ENDPOINT = 'http://169.254.169.254/metadata/identity/oauth2/token'
              IMDS_API_VERSION = '2019-08-01'

              def acquire_managed_token(resource: 'https://graph.microsoft.com', client_id: nil, **)
                log.debug("ManagedIdentity::Token.acquire: resource=#{resource}")
                params = {
                  'api-version' => IMDS_API_VERSION,
                  'resource'    => resource
                }
                params['client_id'] = client_id if client_id

                response = imds_connection.get('metadata/identity/oauth2/token', params)
                body = response.body.to_s.empty? ? {} : json_load(response.body)

                unless response.success?
                  log.warn("ManagedIdentity::Token.acquire: IMDS returned #{response.status}")
                  return { error:       "http_#{response.status}",
                           description: body[:error_description] || response.reason_phrase }
                end

                log.info('ManagedIdentity::Token.acquire: token acquired from IMDS')
                { result: body }
              rescue StandardError => e
                handle_exception(e, level: :error, operation: 'managed_identity.token.acquire')
                { error: 'request_failed', description: e.message }
              end

              private

              def imds_connection
                Faraday.new(url: 'http://169.254.169.254/') do |f|
                  f.headers['Metadata'] = 'true'
                  f.headers['Accept'] = 'application/json'
                  f.options.open_timeout = 2
                  f.options.timeout = 5
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
