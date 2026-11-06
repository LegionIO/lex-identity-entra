# frozen_string_literal: true

require 'faraday'
require 'base64'

module Legion
  module Extensions
    module Identity
      module Entra
        module Helpers
          module GraphClient
            extend self
            include Legion::Logging::Helper
            include Legion::Settings::Helper
            include Legion::JSON::Helper

            ME_SELECT = 'id,displayName,mail,employeeId,onPremisesSamAccountName,' \
                        'onPremisesDomainName,mailNickname,department,jobTitle,companyName'

            def fetch_me(access_token)
              log.debug('GraphClient.fetch_me: requesting /me profile from Microsoft Graph')
              response = graph_connection(access_token).get("me?$select=#{ME_SELECT}")

              unless response.success?
                log.warn("GraphClient.fetch_me: Graph API returned #{response.status}")
                return nil
              end

              log.debug('GraphClient.fetch_me: profile fetched successfully')
              profile = parse_profile(json_load(response.body))
              profile.merge(authenticated_subject(access_token: access_token, object_id: profile[:id]))
            rescue StandardError => e
              handle_exception(e, level: :warn, operation: 'graph_client.fetch_me')
              nil
            end

            def parse_profile(data)
              {
                id:                           data[:id],
                display_name:                 data[:displayName] || data[:display_name],
                mail:                         data[:mail],
                employee_id:                  data[:employeeId] || data[:employee_id],
                on_premises_sam_account_name: data[:onPremisesSamAccountName] || data[:on_premises_sam_account_name],
                on_premises_domain_name:      data[:onPremisesDomainName] || data[:on_premises_domain_name],
                mail_nickname:                data[:mailNickname] || data[:mail_nickname],
                department:                   data[:department],
                job_title:                    data[:jobTitle] || data[:job_title],
                company_name:                 data[:companyName] || data[:company_name]
              }
            end

            def graph_connection(access_token)
              Faraday.new(url: Legion::Extensions::Identity::Entra::Client::GRAPH_BASE) do |f|
                f.headers['Authorization'] = "Bearer #{access_token}"
                f.headers['Accept'] = 'application/json'
                f.options.open_timeout = 5
                f.options.timeout = 10
              end
            end

            private

            # Graph has accepted this exact bearer token. Only then may its tenant/object
            # claims qualify the /me subject; configured tenants and names are not evidence.
            def authenticated_subject(access_token:, object_id:)
              parts = access_token.to_s.split('.')
              return {} unless parts.length == 3

              claims = json_load(Base64.urlsafe_decode64(parts[1]))
              tenant = claims[:tid].to_s.downcase
              oid = claims[:oid].to_s.downcase
              guid = /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/
              unless guid.match?(tenant) && guid.match?(oid) && oid == object_id.to_s.downcase
                log.warn('Graph /me subject does not have matching tenant/object token claims')
                return {}
              end

              { tenant_id: tenant, object_id: oid, provider_identity_key: "#{tenant}:#{oid}" }
            rescue StandardError => e
              log.warn("Graph /me subject context unavailable: #{e.class}")
              {}
            end
          end
        end
      end
    end
  end
end
