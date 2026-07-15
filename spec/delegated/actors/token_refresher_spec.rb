# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe Legion::Extensions::Identity::Entra::Delegated::Actor::TokenRefresher do
  subject(:refresher) { described_class.allocate }

  let(:manager) { Legion::Extensions::Identity::Entra::Helpers::TokenManager }
  let(:tmpdir) { Dir.mktmpdir('entra-tokens') }

  before do
    stub_const('Legion::Extensions::Identity::Entra::Helpers::TokenManager::TOKEN_DIR', tmpdir)
    allow(Legion::Crypt).to receive(:vault_connected?).and_return(false)
    allow(manager).to receive(:current_scope_fingerprint).and_return('test-fingerprint')
    manager.memory_store.clear
    refresher.define_singleton_method(:log) { Logger.new(File::NULL) }
  end

  after do
    FileUtils.rm_rf(tmpdir)
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
  end
end
