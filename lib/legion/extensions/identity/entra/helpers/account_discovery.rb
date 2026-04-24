# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module Helpers
          # Multi-account discovery for Entra ID.
          #
          # Detects privileged accounts (e.g. adm-* / priv-* patterns) by iterating
          # stored tokens. Full implementation is a follow-up; this scaffold provides
          # the interface contract.
          module AccountDiscovery
            module_function

            # Returns an array of qualifier symbols for which tokens exist locally.
            def discovered_qualifiers
              return [] unless File.directory?(TokenManager::TOKEN_DIR)

              Dir.glob(File.join(TokenManager::TOKEN_DIR, 'entra_*.json')).filter_map do |path|
                basename = File.basename(path, '.json')
                match = basename.match(/\Aentra_(.+)\z/)
                match[1].to_sym if match
              end
            end

            # Resolves identity for each discovered qualifier, returning an array of
            # identity hashes (nils filtered out).
            def resolve_all_accounts
              discovered_qualifiers.filter_map do |qualifier|
                token = TokenManager.load_token(qualifier)
                next unless token

                profile = GraphClient.fetch_me(token)
                next unless profile

                canonical = profile[:on_premises_sam_account_name] || profile[:mail_nickname]
                next if canonical.nil? || canonical.empty?

                {
                  canonical_name:    Identity.normalize(canonical),
                  kind:              :human,
                  source:            :entra,
                  qualifier:         qualifier,
                  provider_identity: profile[:id],
                  profile:           profile,
                  employee_id:       profile[:employee_id]
                }
              end
            end
          end
        end
      end
    end
  end
end
