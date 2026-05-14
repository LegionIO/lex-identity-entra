# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module Delegated
          module Identity
            extend self
            include Legion::Logging::Helper
            include Legion::Settings::Helper

            def provider_name  = :entra_delegated
            def provider_type  = :auth
            def priority       = 100
            def trust_weight   = 40
            def trust_level    = :verified
            def capabilities   = %i[authenticate profile interactive outbound_auth]

            def resolve
              log.debug('Delegated::Identity.resolve: starting identity resolution')
              token = find_cached_token
              unless token
                log.debug('Delegated::Identity.resolve: no cached token, cannot resolve')
                return nil
              end

              profile = Legion::Extensions::Identity::Entra::Helpers::GraphClient.fetch_me(token)
              unless profile
                log.warn('Delegated::Identity.resolve: Graph /me returned nil')
                return nil
              end

              canonical = profile[:on_premises_sam_account_name] || profile[:mail_nickname]
              if canonical.nil? || canonical.empty?
                log.warn('Delegated::Identity.resolve: no canonical name in profile')
                return nil
              end

              log.info("Delegated::Identity.resolve: resolved identity canonical=#{normalize(canonical)}")
              {
                canonical_name:    normalize(canonical),
                kind:              :human,
                source:            :entra_delegated,
                provider_identity: profile[:id],
                profile:           profile,
                employee_id:       profile[:employee_id]
              }
            end

            def resolve_all
              accounts = Legion::Extensions::Identity::Entra::Helpers::AccountDiscovery.resolve_all_accounts
              return accounts unless accounts.empty?

              result = resolve
              result ? [result] : []
            end

            def refresh
              log.debug('Delegated::Identity.refresh: attempting token refresh')
              data = Legion::Extensions::Identity::Entra::Helpers::TokenManager.token_data(:delegated, refresh: true)
              if data && !Legion::Extensions::Identity::Entra::Helpers::TokenManager.expired?(data)
                Legion::Extensions::Identity::Entra::Client.reset!(pattern: :delegated)
                log.info('Delegated::Identity.refresh: token refreshed successfully')
                true
              else
                log.warn('Delegated::Identity.refresh: token refresh returned expired or nil data')
                false
              end
            rescue StandardError => e
              handle_exception(e, level: :warn, operation: 'delegated.identity.refresh')
              false
            end

            def normalize(val)
              str = val.to_s.downcase.strip
              str = str.split('@', 2).first if str.include?('@')
              str.gsub(/[^a-z0-9_-]/, '')
            end

            def provide_token(qualifier: :delegated)
              token = find_cached_token(qualifier)
              return nil unless token

              data = Legion::Extensions::Identity::Entra::Helpers::TokenManager.token_data(qualifier, refresh: false)
              build_lease(
                provider:   :entra_delegated,
                credential: token,
                expires_at: data&.dig(:expires_at) || (Time.now + 3600),
                renewable:  !data&.dig(:refresh_token).nil?,
                metadata:   { qualifier: qualifier, scopes: data&.dig(:scopes) }.compact
              )
            end

            private

            def find_cached_token(qualifier = :delegated)
              log.debug("Delegated::Identity.find_cached_token: qualifier=#{qualifier}")
              Legion::Extensions::Identity::Entra::Helpers::TokenManager.load_token(qualifier)
            rescue StandardError => e
              handle_exception(e, level: :warn, operation: 'delegated.identity.find_cached_token',
                                  qualifier: qualifier)
              nil
            end

            def build_lease(**attrs)
              return Legion::Identity::Lease.new(**attrs) if defined?(Legion::Identity::Lease)

              attrs
            end
          end
        end
      end
    end
  end
end
