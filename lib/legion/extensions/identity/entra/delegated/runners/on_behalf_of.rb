# frozen_string_literal: true

require 'faraday'

module Legion
  module Extensions
    module Identity
      module Entra
        module Delegated
          module Runners
            module OnBehalfOf
              include Legion::Logging::Helper
              include Legion::Settings::Helper

              def exchange_on_behalf_of(tenant_id:, client_id:, client_secret:,
                                        assertion:, scope:, **)
                log.debug("OnBehalfOf.exchange: tenant=#{tenant_id} scope=#{scope}")
                result = obo_post(tenant_id,
                                  grant_type:          'urn:ietf:params:oauth:grant-type:jwt-bearer',
                                  client_id:           client_id,
                                  client_secret:       client_secret,
                                  assertion:           assertion,
                                  scope:               scope,
                                  requested_token_use: 'on_behalf_of')
                log.info('OnBehalfOf.exchange: token exchanged successfully') if result[:access_token]
                { result: result }
              rescue StandardError => e
                handle_exception(e, level: :error, operation: 'delegated.on_behalf_of.exchange')
                { error: 'request_failed', description: e.message }
              end

              def obo_post(tenant_id, form)
                log.debug("OnBehalfOf.obo_post: tenant=#{tenant_id}")
                response = obo_connection(tenant_id).post('oauth2/v2.0/token',
                                                          URI.encode_www_form(form.transform_keys(&:to_s)))
                body = response.body.to_s.empty? ? {} : json_load(response.body)
                unless response.success?
                  body[:error] ||= "http_#{response.status}"
                  body[:error_description] ||= response.reason_phrase
                  log.debug("OnBehalfOf.obo_post: error=#{body[:error]} status=#{response.status}")
                end
                body
              end

              private

              def obo_connection(tenant_id)
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
