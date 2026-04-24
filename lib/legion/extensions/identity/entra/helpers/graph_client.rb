# frozen_string_literal: true

require 'net/http'
require 'json'
require 'uri'

module Legion
  module Extensions
    module Identity
      module Entra
        module Helpers
          module GraphClient
            GRAPH_BASE = 'https://graph.microsoft.com/v1.0'
            ME_SELECT  = 'id,displayName,mail,employeeId,onPremisesSamAccountName,' \
                         'onPremisesDomainName,mailNickname,department,jobTitle,companyName'

            module_function

            def fetch_me(access_token)
              uri  = URI("#{GRAPH_BASE}/me?$select=#{ME_SELECT}")
              http = Net::HTTP.new(uri.host, uri.port)
              http.use_ssl      = true
              http.open_timeout = 5
              http.read_timeout = 10

              request = Net::HTTP::Get.new(uri)
              request['Authorization'] = "Bearer #{access_token}"
              request['Accept']        = 'application/json'

              response = http.request(request)
              return nil unless response.is_a?(Net::HTTPSuccess)

              parse_profile(::JSON.parse(response.body))
            rescue StandardError => _e
              nil
            end

            def parse_profile(data)
              {
                id:                           data['id'],
                display_name:                 data['displayName'],
                mail:                         data['mail'],
                employee_id:                  data['employeeId'],
                on_premises_sam_account_name: data['onPremisesSamAccountName'],
                on_premises_domain_name:      data['onPremisesDomainName'],
                mail_nickname:                data['mailNickname'],
                department:                   data['department'],
                job_title:                    data['jobTitle'],
                company_name:                 data['companyName']
              }
            end
          end
        end
      end
    end
  end
end
