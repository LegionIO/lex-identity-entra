# frozen_string_literal: true

require 'faraday'

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
              parse_profile(json_load(response.body))
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
          end
        end
      end
    end
  end
end
