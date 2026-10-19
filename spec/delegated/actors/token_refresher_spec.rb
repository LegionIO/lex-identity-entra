# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Legion::Extensions::Identity::Entra::Delegated::Actor::TokenRefresher do
  subject(:refresher) { described_class.allocate }

  let(:manager) { Legion::Extensions::Identity::Entra::Helpers::TokenManager }

  before do
    allow(Legion::Crypt).to receive(:vault_connected?).and_return(false)
    allow(manager).to receive(:current_scope_fingerprint).and_return('test-fingerprint')
    manager.memory_store.clear
    refresher.define_singleton_method(:log) { Logger.new(File::NULL) }
  end

  describe '#manual' do
    context 'when no stored token data exists' do
      it 'skips without attempting refresh' do
        expect(manager).not_to receive(:token_data).with(:delegated, refresh: true)
        refresher.manual
      end
    end

    context 'when stored token has no refresh_token' do
      before do
        manager.save_to_memory(:delegated, access_token:      'expired',
                                           refresh_token:     nil,
                                           expires_at:        Time.now - 3600,
                                           scope_fingerprint: 'test-fingerprint')
      end

      it 'skips without attempting refresh' do
        expect(manager).not_to receive(:token_data).with(:delegated, refresh: true)
        refresher.manual
      end
    end

    context 'when stored token is valid and fingerprint matches' do
      before do
        manager.save_to_memory(:delegated, access_token:      'valid-token',
                                           refresh_token:     'refresh-token',
                                           expires_at:        Time.now + 3600,
                                           scope_fingerprint: 'test-fingerprint')
      end

      it 'does not attempt refresh' do
        expect(manager).not_to receive(:token_data).with(:delegated, refresh: true)
        refresher.manual
      end
    end

    context 'when stored token is expired and has a refresh_token' do
      before do
        manager.save_to_memory(:delegated, access_token:      'expired-token',
                                           refresh_token:     'valid-refresh',
                                           expires_at:        Time.now - 3600,
                                           scopes:            'User.Read offline_access',
                                           tenant_id:         'tenant-1',
                                           client_id:         'client-1',
                                           scope_fingerprint: 'test-fingerprint')
        allow(manager).to receive(:token_data).with(:delegated, refresh: true).and_return(
          { access_token: 'refreshed', refresh_token: 'new-refresh',
            expires_at: Time.now + 3600, scope_fingerprint: 'test-fingerprint' }
        )
        allow(Legion::Extensions::Identity::Entra::Client).to receive(:reset!)
      end

      it 'attempts token refresh via token_data' do
        refresher.manual
        expect(manager).to have_received(:token_data).with(:delegated, refresh: true)
      end

      it 'resets the client on success' do
        refresher.manual
        expect(Legion::Extensions::Identity::Entra::Client).to have_received(:reset!).with(pattern: :delegated)
      end
    end

    context 'when scope fingerprint is stale and token has a refresh_token' do
      before do
        manager.save_to_memory(:delegated, access_token:      'valid-token',
                                           refresh_token:     'valid-refresh',
                                           expires_at:        Time.now + 3600,
                                           scopes:            'User.Read offline_access',
                                           tenant_id:         'tenant-1',
                                           client_id:         'client-1',
                                           scope_fingerprint: 'old-fingerprint')
        allow(manager).to receive(:current_scope_fingerprint).and_return('new-fingerprint')
        allow(manager).to receive(:token_data).with(:delegated, refresh: true).and_return(
          { access_token: 'refreshed-scopes', refresh_token: 'new-refresh',
            expires_at: Time.now + 3600, scope_fingerprint: 'new-fingerprint' }
        )
        allow(Legion::Extensions::Identity::Entra::Client).to receive(:reset!)
      end

      it 'detects stale fingerprint and triggers refresh via token_data' do
        refresher.manual
        expect(manager).to have_received(:token_data).with(:delegated, refresh: true)
      end
    end

    context 'when refresh fails' do
      let(:browser) { instance_double(Legion::Extensions::Identity::Entra::Helpers::BrowserAuth) }
      let(:guard) { Legion::Extensions::Identity::Entra::Helpers::InteractiveAuthGuard }
      let(:log_io) { StringIO.new }

      before do
        log = Logger.new(log_io)
        refresher.define_singleton_method(:log) { log }
        allow(guard).to receive(:log).and_return(log)
        manager.save_to_memory(:delegated, access_token:      'expired-token',
                                           refresh_token:     'dead-refresh',
                                           expires_at:        Time.now - 3600,
                                           scope_fingerprint: 'test-fingerprint')
        allow(manager).to receive(:token_data).with(:delegated, refresh: true).and_return(nil)
        allow(manager).to receive(:settings_auth).and_return(tenant_id: 'tenant-1', client_id: 'client-1')
        allow(Legion::Extensions::Identity::Entra::Helpers::BrowserAuth).to receive(:new).and_return(browser)
        allow(browser).to receive(:authenticate).and_return(error: 'timeout')
        allow(Legion::Settings).to receive(:dig).and_call_original
      end

      def stub_auto_authenticate(value)
        allow(Legion::Settings).to receive(:dig)
          .with(:identity, :entra, :delegated, :browser_auth, :auto_authenticate).and_return(value)
      end

      it 'does not open a browser when auto_authenticate is false and logs one re-auth hint' do
        stub_auto_authenticate(false)
        3.times { refresher.manual }

        expect(Legion::Extensions::Identity::Entra::Helpers::BrowserAuth).not_to have_received(:new)
        expect(log_io.string.scan('legionio auth teams').size).to eq(1)
      end

      it 'marks the browser attempt as automatic when auto_authenticate is true' do
        stub_auto_authenticate(true)
        refresher.manual

        expect(Legion::Extensions::Identity::Entra::Helpers::BrowserAuth).to have_received(:new)
          .with(hash_including(automatic: true))
      end

      it 'opens at most one tab across many ticks after a timeout (backoff)' do
        stub_auto_authenticate(true)
        allow(Legion::Extensions::Identity::Entra::Helpers::BrowserAuth).to receive(:new).and_call_original
        opened = 0
        allow_any_instance_of(Legion::Extensions::Identity::Entra::Helpers::BrowserAuth)
          .to receive(:authenticate_browser) { opened += 1 and { error: 'timeout' } }
        allow_any_instance_of(Legion::Extensions::Identity::Entra::Helpers::BrowserAuth)
          .to receive(:gui_available?).and_return(true)

        50.times { refresher.manual }

        expect(opened).to eq(1)
        expect(guard.state[:failures]).to eq(1)
      end
    end
  end
end
