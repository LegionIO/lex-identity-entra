# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module Identity
          extend self

          def provider_name  = :entra
          def provider_type  = :auth
          def priority       = 100
          def trust_weight   = 40
          def trust_level    = :verified
          def capabilities   = %i[authenticate profile interactive outbound_auth]

          # Returns a resolved identity hash or nil when no cached Entra token is available.
          #
          # Hash shape:
          #   { canonical_name:, kind: :human, source: :entra, provider_identity:, profile:, employee_id: }
          #
          # canonical_name regex: ^[a-z0-9][a-z0-9_-]*$ (no dots -- AMQP word separator)
          def resolve
            token = find_cached_token
            return nil unless token

            profile = Helpers::GraphClient.fetch_me(token)
            return nil unless profile

            canonical = profile[:on_premises_sam_account_name] || profile[:mail_nickname]
            return nil if canonical.nil? || canonical.empty?

            {
              canonical_name:    normalize(canonical),
              kind:              :human,
              source:            :entra,
              provider_identity: profile[:id],
              profile:           profile,
              employee_id:       profile[:employee_id]
            }
          end

          # Multi-account discovery -- returns array of identity hashes.
          # For now wraps resolve in an array. Full multi-account (priv accounts)
          # requires iterating stored tokens for each account.
          def resolve_all
            result = resolve
            result ? [result] : []
          end

          # Strips @domain, downcases, removes non-word chars (no dots -- AMQP word separator).
          def normalize(val)
            str = val.to_s.downcase.strip
            str = str.split('@', 2).first if str.include?('@')
            str.gsub(/[^a-z0-9_-]/, '')
          end

          # Returns a Lease-like hash (or Legion::Identity::Lease) carrying the cached access token.
          def provide_token
            token = find_cached_token
            return nil unless token

            build_lease(
              provider:   :entra,
              credential: token,
              expires_at: Time.now + 3600,
              renewable:  true,
              metadata:   {}
            )
          end

          private

          def find_cached_token
            Helpers::TokenManager.load_token(:delegated)
          rescue StandardError => _e
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
