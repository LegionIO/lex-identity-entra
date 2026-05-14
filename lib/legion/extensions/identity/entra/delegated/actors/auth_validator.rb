# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module Delegated
          module Actor
            class AuthValidator < Legion::Extensions::Actors::Once
              def runner_class    = self.class
              def runner_function = 'manual'
              def use_runner?     = false
              def check_subtask?  = false
              def generate_task?  = false

              def delay
                9.0
              end

              def enabled? # rubocop:disable Legion/Extension/ActorEnabledSideEffects
                true
              end

              def manual
                log.info('Entra Delegated AuthValidator starting')
                client = Legion::Extensions::Identity::Entra::Client.instance(pattern: :delegated)

                if Legion::Extensions::Identity::Entra::Helpers::TokenManager.authenticated?(:delegated)
                  token = client.access_token
                  if token
                    log.info('Entra delegated auth valid')
                    upgrade_identity
                  elsif auto_authenticate?
                    log.info('Entra delegated token expired, attempting browser re-auth')
                    attempt_browser_reauth
                  end
                elsif previously_authenticated?
                  if Legion::Extensions::Identity::Entra::Helpers::TokenManager.scope_fingerprint_stale?(:delegated)
                    log.info('Entra delegated scope fingerprint changed, re-authenticating to acquire updated scopes')
                  else
                    log.info('Entra delegated token file found but expired, attempting re-auth')
                  end
                  attempt_browser_reauth
                elsif auto_authenticate?
                  log.info('auto_authenticate enabled, opening browser for initial auth')
                  attempt_browser_reauth
                else
                  log.debug('No Entra delegated auth configured, skipping')
                end
                log.info('Entra Delegated AuthValidator complete')
              rescue StandardError => e
                log.error("AuthValidator: #{e.message}")
              end

              private

              def attempt_browser_reauth
                auth_settings = Legion::Extensions::Identity::Entra::Helpers::TokenManager.settings_auth
                unless auth_settings[:tenant_id] && auth_settings[:client_id]
                  log.warn('Cannot re-auth: missing tenant_id or client_id')
                  return false
                end

                scopes = Legion::Extensions::Identity::Entra::Helpers::Scopes.resolve(pattern: :delegated)
                browser = Legion::Extensions::Identity::Entra::Helpers::BrowserAuth.new(
                  tenant_id: auth_settings[:tenant_id],
                  client_id: auth_settings[:client_id],
                  scopes:    scopes
                )

                result = browser.authenticate
                if result[:error]
                  log.error("Browser auth error: #{result[:error]} - #{result[:description]}")
                  return false
                end

                body = result[:result]
                Legion::Extensions::Identity::Entra::Helpers::TokenManager.save_token(
                  :delegated,
                  access_token:  body[:access_token],
                  refresh_token: body[:refresh_token],
                  expires_in:    body[:expires_in],
                  scopes:        body[:scope] || scopes,
                  tenant_id:     auth_settings[:tenant_id],
                  client_id:     auth_settings[:client_id]
                )
                Legion::Extensions::Identity::Entra::Client.reset!(pattern: :delegated)
                upgrade_identity
                log.info('Entra delegated auth restored via browser')
                true
              rescue StandardError => e
                log.error("Browser re-auth failed: #{e.message}")
                false
              end

              def upgrade_identity
                return unless defined?(Legion::Identity::Resolver)

                identity_module = Legion::Extensions::Identity::Entra::Delegated::Identity
                result = identity_module.resolve
                unless result
                  log.warn('AuthValidator.upgrade_identity: resolve returned nil, skipping upgrade')
                  return
                end

                Legion::Identity::Resolver.upgrade!(identity_module, result)
                log.info("AuthValidator.upgrade_identity: identity upgraded canonical=#{result[:canonical_name]}")
                register_broker
              rescue StandardError => e
                log.error("AuthValidator.upgrade_identity failed: #{e.message}")
              end

              def register_broker
                return unless defined?(Legion::Identity::Broker)

                identity_module = Legion::Extensions::Identity::Entra::Delegated::Identity
                lease = identity_module.provide_token(qualifier: :delegated)
                unless lease
                  log.warn('AuthValidator.register_broker: provide_token returned nil, skipping broker registration')
                  return
                end

                Legion::Identity::Broker.register_provider(
                  :entra_delegated,
                  provider:  identity_module,
                  lease:     lease,
                  qualifier: :delegated,
                  default:   true
                )
                log.info('AuthValidator.register_broker: entra_delegated registered with broker qualifier=delegated')
              rescue StandardError => e
                log.error("AuthValidator.register_broker failed: #{e.message}")
              end

              def auto_authenticate?
                Legion::Settings.dig(:identity, :entra, :delegated, :browser_auth, :auto_authenticate) == true
              end

              def previously_authenticated?
                path = Legion::Extensions::Identity::Entra::Helpers::TokenManager.local_path(:delegated)
                File.exist?(path)
              end
            end
          end
        end
      end
    end
  end
end
