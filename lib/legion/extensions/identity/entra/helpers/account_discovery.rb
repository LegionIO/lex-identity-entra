# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module Helpers
          # Multi-account discovery for Entra ID.
          #
          # Detects primary and privileged accounts by iterating stored delegated
          # token qualifiers and resolving each qualifier through Graph /me.
          module AccountDiscovery
            extend self
            include Legion::Logging::Helper
            include Legion::Settings::Helper
            include Legion::Extensions::Helpers::Lex if Legion::Extensions.const_defined?(:Helpers, false) &&
                                                        Legion::Extensions::Helpers.const_defined?(:Lex, false)

            # Returns an array of qualifier symbols for which tokens exist locally.
            def discovered_qualifiers
              (local_qualifiers + broker_qualifiers).uniq
            end

            def local_qualifiers
              return [] unless File.directory?(Legion::Extensions::Identity::Entra::Helpers::TokenManager::TOKEN_DIR)

              Dir.glob(File.join(Legion::Extensions::Identity::Entra::Helpers::TokenManager::TOKEN_DIR, 'entra_*.json')).filter_map do |path|
                basename = File.basename(path, '.json')
                match = basename.match(/\Aentra_(.+)\z/)
                match[1].to_sym if match
              end
            end

            def broker_qualifiers
              return [] unless defined?(Legion::Identity::Broker)
              return [] unless Legion::Identity::Broker.respond_to?(:credentials_available)

              Legion::Identity::Broker.credentials_available(:entra)
            rescue StandardError => e
              handle_exception(e, level: :warn, operation: 'account_discovery.broker_qualifiers')
              []
            end

            # Resolves identity for each discovered qualifier, returning an array of
            # identity hashes (nils filtered out).
            def resolve_all_accounts
              discovered_qualifiers.filter_map do |qualifier|
                token = Legion::Extensions::Identity::Entra::Helpers::TokenManager.load_token(qualifier)
                next unless token

                profile = Legion::Extensions::Identity::Entra::Helpers::GraphClient.fetch_me(token)
                next unless profile

                canonical = profile[:on_premises_sam_account_name] || profile[:mail_nickname]
                next if canonical.nil? || canonical.empty?

                {
                  canonical_name:    Legion::Extensions::Identity::Entra::Delegated::Identity.normalize(canonical),
                  kind:              :human,
                  source:            :entra,
                  qualifier:         qualifier,
                  account_type:      account_type_for(qualifier, canonical),
                  provider_identity: profile[:id],
                  profile:           profile,
                  employee_id:       profile[:employee_id]
                }
              end
            end

            def account_type_for(qualifier, canonical)
              value = [qualifier, canonical].compact.join(' ')
              return 'privileged' if value.match?(/\b(adm|admin|priv|svc)[_-]/i)

              qualifier.to_sym == :delegated ? 'primary' : 'secondary'
            end

            def log_debug(message)
              log.debug("[Entra::AccountDiscovery] #{message}")
            end
          end
        end
      end
    end
  end
end
