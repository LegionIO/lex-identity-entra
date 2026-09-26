# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Legion::Extensions::Identity::Entra::Helpers::TokenManager do
  subject(:manager) { described_class }

  before do
    # Ensure vault is unavailable by default so tests don't attempt real vault calls
    allow(Legion::Crypt).to receive(:vault_connected?).and_return(false)
    # Stub scope fingerprint so tokens without a stored fingerprint aren't treated as stale
    allow(described_class).to receive(:current_scope_fingerprint).and_return('test-fingerprint')
    # Reset in-memory store between examples
    described_class.memory_store.clear
  end

  # ---- load_token ----

  describe '.load_token' do
    context 'when no Vault and no in-memory token exist' do
      it 'returns nil' do
        expect(manager.load_token(:delegated)).to be_nil
      end
    end

    context 'when a valid in-memory token exists' do
      before do
        manager.save_to_memory(:delegated, access_token:      'local-token-abc',
                                           refresh_token:     'refresh-xyz',
                                           expires_at:        Time.now + 3600,
                                           scope_fingerprint: 'test-fingerprint')
      end

      it 'returns the access token from the in-memory store' do
        expect(manager.load_token(:delegated)).to eq('local-token-abc')
      end
    end

    context 'when the in-memory token is expired' do
      before do
        manager.save_to_memory(:delegated, access_token:  'expired-token',
                                           refresh_token: nil,
                                           expires_at:    Time.now - 3600)
      end

      it 'returns nil' do
        expect(manager.load_token(:delegated)).to be_nil
      end
    end

    context 'when the in-memory token has no expires_at' do
      before do
        manager.save_to_memory(:delegated, access_token:      'no-expiry-token',
                                           refresh_token:     nil,
                                           expires_at:        nil,
                                           scope_fingerprint: 'test-fingerprint')
      end

      it 'returns the token (no expiry check)' do
        expect(manager.load_token(:delegated)).to eq('no-expiry-token')
      end
    end

    context 'when the broker has a delegated token' do
      before do
        broker = double('broker')
        stub_const('Legion::Identity::Broker', broker)
        allow(broker).to receive(:token_for)
          .with(:entra_delegated, qualifier: :delegated).and_return('broker-token')
      end

      it 'falls back to the broker after Vault and local file miss' do
        expect(manager.load_token(:delegated)).to eq('broker-token')
      end
    end

    context 'when the broker only registered under the auth actor provider name' do
      before do
        # AuthValidator#register_broker registers :entra_delegated. The token
        # manager must request that exact provider name — a lookup under :entra
        # would miss the registered provider (issue #5).
        broker = double('broker')
        stub_const('Legion::Identity::Broker', broker)
        allow(broker).to receive(:token_for)
          .with(:entra, qualifier: :delegated).and_return(nil)
        allow(broker).to receive(:token_for)
          .with(:entra_delegated, qualifier: :delegated).and_return('broker-token')
      end

      it 'requests the same provider name the auth actor registers' do
        expect(manager.load_token(:delegated)).to eq('broker-token')
      end
    end

    context 'when an in-memory token is expired but refreshable' do
      before do
        manager.save_to_memory(:delegated, access_token:      'expired-token',
                                           refresh_token:     'refresh-token',
                                           expires_at:        Time.now - 3600,
                                           scopes:            'User.Read offline_access',
                                           tenant_id:         'tenant-1',
                                           client_id:         'client-1',
                                           scope_fingerprint: 'test-fingerprint')

        allow(manager).to receive(:refresh_token).and_return(
          {
            access_token:  'fresh-token',
            refresh_token: 'fresh-refresh-token',
            expires_at:    Time.now + 3600,
            scopes:        'User.Read offline_access',
            tenant_id:     'tenant-1',
            client_id:     'client-1'
          }
        )
      end

      it 'refreshes and returns the new access token' do
        expect(manager.load_token(:delegated)).to eq('fresh-token')
      end
    end

    context 'when vault saves token during refresh' do
      before do
        manager.save_to_memory(:delegated, access_token:      'expired-token',
                                           refresh_token:     'refresh-token',
                                           expires_at:        Time.now - 3600,
                                           scopes:            'User.Read offline_access',
                                           tenant_id:         'tenant-1',
                                           client_id:         'client-1',
                                           scope_fingerprint: 'test-fingerprint')

        # Simulate: save_to_vault succeeds, save_to_memory runs
        allow(manager).to receive(:refresh_token) do |qualifier, _data|
          manager.save_to_vault(qualifier, access_token:  'refreshed-via-vault',
                                           refresh_token: 'new-refresh',
                                           expires_at:    Time.now + 3600,
                                           scopes:        'User.Read offline_access',
                                           tenant_id:     'tenant-1',
                                           client_id:     'client-1')
          manager.save_to_memory(qualifier, access_token:      'refreshed-via-vault',
                                            refresh_token:     'new-refresh',
                                            expires_at:        Time.now + 3600,
                                            scopes:            'User.Read offline_access',
                                            tenant_id:         'tenant-1',
                                            client_id:         'client-1',
                                            scope_fingerprint: 'test-fingerprint')
          manager.from_memory(qualifier)
        end
      end

      it 'returns the refreshed token from memory' do
        expect(manager.load_token(:delegated)).to eq('refreshed-via-vault')
      end
    end
  end

  # ---- save_token ----

  describe '.save_token' do
    it 'stores the access_token in memory when vault is unavailable' do
      manager.save_token(:delegated, access_token: 'save-test', refresh_token: 'refresh',
                                     expires_at: Time.now + 7200)
      expect(manager.from_memory(:delegated)[:access_token]).to eq('save-test')
    end

    it 'stores the refresh_token' do
      manager.save_token(:delegated, access_token: 'a', refresh_token: 'my-refresh',
                                     expires_at: Time.now + 7200)
      expect(manager.from_memory(:delegated)[:refresh_token]).to eq('my-refresh')
    end

    it 'stores the expires_at' do
      expires = Time.now + 7200
      manager.save_token(:delegated, access_token: 'a', refresh_token: nil, expires_at: expires)
      expect(manager.from_memory(:delegated)[:expires_at]).to eq(Time.parse(expires.utc.iso8601))
    end

    it 'stores scopes and client metadata when provided' do
      manager.save_token(:delegated, access_token: 'a', refresh_token: nil, expires_at: Time.now + 7200,
                                     scopes: 'User.Read', tenant_id: 'tenant-1', client_id: 'client-1')
      expect(manager.from_memory(:delegated)).to include(scopes:    'User.Read',
                                                         tenant_id: 'tenant-1',
                                                         client_id: 'client-1')
    end
  end

  # ---- scope fingerprint mismatch with refresh_token (issue #7 / E1) ----

  describe '.token_data scope fingerprint mismatch' do
    context 'when fingerprint is stale but refresh_token is present and refresh: true' do
      before do
        manager.save_to_memory(:delegated, access_token:      'stale-fp-token',
                                           refresh_token:     'valid-refresh',
                                           expires_at:        Time.now + 3600,
                                           scopes:            'User.Read offline_access',
                                           tenant_id:         'tenant-1',
                                           client_id:         'client-1',
                                           scope_fingerprint: 'old-fingerprint')
        allow(described_class).to receive(:current_scope_fingerprint).and_return('new-fingerprint')
        allow(described_class).to receive(:refresh_token).and_return(
          {
            access_token:  'refreshed-after-fp-change',
            refresh_token: 'new-refresh',
            expires_at:    Time.now + 3600,
            scopes:        'User.Read offline_access Mail.Read',
            tenant_id:     'tenant-1',
            client_id:     'client-1'
          }
        )
      end

      it 'attempts refresh instead of returning nil' do
        result = manager.token_data(:delegated, refresh: true)
        expect(result[:access_token]).to eq('refreshed-after-fp-change')
        expect(described_class).to have_received(:refresh_token)
      end
    end

    context 'when fingerprint is stale, refresh_token is present, but refresh: false' do
      before do
        manager.save_to_memory(:delegated, access_token:      'stale-fp-token',
                                           refresh_token:     'valid-refresh',
                                           expires_at:        Time.now + 3600,
                                           scopes:            'User.Read offline_access',
                                           tenant_id:         'tenant-1',
                                           client_id:         'client-1',
                                           scope_fingerprint: 'old-fingerprint')
        allow(described_class).to receive(:current_scope_fingerprint).and_return('new-fingerprint')
      end

      it 'returns nil (no refresh attempted)' do
        result = manager.token_data(:delegated, refresh: false)
        expect(result).to be_nil
      end
    end

    context 'when fingerprint is stale and no refresh_token is present' do
      before do
        manager.save_to_memory(:delegated, access_token:      'stale-fp-token',
                                           refresh_token:     nil,
                                           expires_at:        Time.now + 3600,
                                           scopes:            'User.Read',
                                           tenant_id:         'tenant-1',
                                           client_id:         'client-1',
                                           scope_fingerprint: 'old-fingerprint')
        allow(described_class).to receive(:current_scope_fingerprint).and_return('new-fingerprint')
      end

      it 'returns nil (forces re-auth)' do
        result = manager.token_data(:delegated, refresh: true)
        expect(result).to be_nil
      end
    end
  end

  # ---- vault_available? ----

  describe '.vault_available?' do
    context 'when vault_connected? returns false (default)' do
      it 'returns false' do
        expect(manager.vault_available?).to be false
      end
    end

    context 'when Legion::Crypt does not respond to vault_connected?' do
      before { stub_const('Legion::Crypt', Module.new) }

      it 'returns false' do
        expect(manager.vault_available?).to be false
      end
    end

    context 'when Legion::Crypt.vault_connected? returns false' do
      before do
        crypt = Module.new { def self.vault_connected? = false }
        stub_const('Legion::Crypt', crypt)
      end

      it 'returns false' do
        expect(manager.vault_available?).to be false
      end
    end

    context 'when Legion::Crypt.vault_connected? returns true and write is available' do
      before do
        crypt = Module.new do
          def self.vault_connected? = true
          def self.write(*) = nil
        end
        stub_const('Legion::Crypt', crypt)
      end

      it 'returns true' do
        expect(manager.vault_available?).to be true
      end
    end
  end

  # ---- vault opt-in flags ----

  describe 'vault opt-in flags' do
    context 'when the flags are not set (default)' do
      it 'leaves vault reads and writes disabled' do
        expect(manager.vault_read_enabled?(:delegated)).to be_falsy
        expect(manager.vault_write_enabled?(:delegated)).to be_falsy
      end

      it 'does not write to vault even when vault is available' do
        allow(described_class).to receive(:vault_available?).and_return(true)
        allow(described_class).to receive(:canonical_name_available?).and_return(true)
        vault_client = double('vault_kv_client')
        allow(vault_client).to receive(:write)
        allow(described_class).to receive(:vault_kv_client).and_return(vault_client)

        result = manager.save_to_vault(:delegated, access_token: 'a', refresh_token: 'r',
                                               expires_at: Time.now + 3600)

        expect(result).to be_nil
        expect(vault_client).not_to have_received(:write)
      end

      it 'does not read from vault even when vault is available' do
        allow(described_class).to receive(:vault_available?).and_return(true)
        allow(described_class).to receive(:canonical_name_available?).and_return(true)
        vault_client = double('vault_kv_client')
        allow(vault_client).to receive(:read)
        allow(described_class).to receive(:vault_kv_client).and_return(vault_client)

        expect(manager.from_vault_data(:delegated)).to be_nil
        expect(vault_client).not_to have_received(:read)
      end
    end

    context 'when both flags are enabled in settings' do
      before do
        @prior_identity = Legion::Settings.get.settings[:identity]
        Legion::Settings.get.settings[:identity] =
          { entra: { delegated: { token: { vault_read_enabled: true, vault_write_enabled: true } } } }
      end

      after do
        Legion::Settings.get.settings[:identity] = @prior_identity
      end

      it 'enables vault reads and writes' do
        expect(manager.vault_read_enabled?(:delegated)).to be true
        expect(manager.vault_write_enabled?(:delegated)).to be true
      end
    end
  end

  # ---- canonical Vault path ----

  describe 'delegated Vault token persistence' do
    let(:vault_client) { double('vault_kv_client') }

    let(:token_body) do
      {
        access_token:      'bootstrap-token',
        refresh_token:     'boot-refresh',
        expires_at:        (Time.now + 3600).utc.iso8601,
        scopes:            'User.Read offline_access',
        tenant_id:         'tenant-1',
        client_id:         'client-1',
        scope_fingerprint: 'test-fingerprint'
      }
    end

    before do
      allow(described_class).to receive(:vault_available?).and_return(true)
      allow(described_class).to receive(:vault_read_enabled?).and_return(true)
      allow(described_class).to receive(:vault_write_enabled?).and_return(true)
      allow(described_class).to receive(:vault_kv_client).and_return(vault_client)
      allow(described_class).to receive(:settings_auth).and_return(tenant_id: 'tenant-1', client_id: 'client-1')
      # save_to_vault reads the cluster name for a log line; keep it off the real
      # Legion::Crypt, which isn't booted in the test env.
      allow(Legion::Crypt).to receive(:respond_to?).and_call_original
      allow(Legion::Crypt).to receive(:respond_to?).with(:default_cluster_name).and_return(true)
      allow(Legion::Crypt).to receive(:default_cluster_name).and_return('vault_test')
    end

    context 'when identity is not yet resolved' do
      before do
        allow(described_class).to receive(:canonical_name_available?).and_return(false)
      end

      it 'does not write a token to Vault without a canonical user path' do
        allow(vault_client).to receive(:write)

        described_class.save_to_vault(:delegated, access_token: 'boot', refresh_token: 'r',
                                                   expires_at: Time.now + 3600, tenant_id: 'tenant-1',
                                                   client_id: 'client-1')

        expect(vault_client).not_to have_received(:write)
      end
    end

    context 'when saving after identity resolves' do
      before do
        allow(described_class).to receive(:canonical_name_available?).and_return(true)
        allow(described_class).to receive(:vault_path).with(:delegated).and_return('users/jdoe/entra/delegated/auth')
      end

      it 'writes only the canonical user key' do
        allow(vault_client).to receive(:write)

        described_class.save_to_vault(:delegated, access_token: 'boot', refresh_token: 'r',
                                                   expires_at: Time.now + 3600, tenant_id: 'tenant-1',
                                                   client_id: 'client-1')

        expect(vault_client).to have_received(:write).with('users/jdoe/entra/delegated/auth', anything)
        expect(vault_client).to have_received(:write).once
      end
    end

    context 'when the canonical token exists' do
      before do
        allow(described_class).to receive(:canonical_name_available?).and_return(true)
        allow(described_class).to receive(:vault_path).with(:delegated).and_return('users/jdoe/entra/delegated/auth')
      end

      it 'reads the canonical key without falling through to bootstrap' do
        allow(vault_client).to receive(:read)
          .with('users/jdoe/entra/delegated/auth').and_return(double('secret', data: token_body))

        expect(described_class.load_token(:delegated)).to eq('bootstrap-token')
        expect(vault_client).to have_received(:read).with('users/jdoe/entra/delegated/auth')
      end
    end
  end

  # ---- vault_path ----

  describe '.vault_path' do
    context 'when Legion::Identity::Process is not defined' do
      before { hide_const('Legion::Identity') }

      it 'returns nil when canonical name is unavailable' do
        expect(manager.vault_path(:delegated)).to be_nil
      end
    end

    context 'when Legion::Identity::Process is resolved' do
      before do
        process = Module.new do
          def self.resolved? = true
          def self.canonical_name = 'testuser'
          def self.trust = :verified
          def self.respond_to?(sym, *) = %i[resolved? canonical_name trust].include?(sym) || super
        end
        stub_const('Legion::Identity::Process', process)
      end

      it 'uses the canonical name in the path' do
        expect(manager.vault_path(:delegated)).to eq('users/testuser/entra/delegated/auth')
      end
    end
  end
end
