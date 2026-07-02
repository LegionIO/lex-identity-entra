# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe Legion::Extensions::Identity::Entra::Helpers::TokenManager do
  subject(:manager) { described_class }

  let(:tmpdir) { Dir.mktmpdir('entra-tokens') }

  before do
    stub_const('Legion::Extensions::Identity::Entra::Helpers::TokenManager::TOKEN_DIR', tmpdir)
    # Ensure vault is unavailable by default so tests don't attempt real vault calls
    allow(Legion::Crypt).to receive(:vault_connected?).and_return(false)
    # Stub scope fingerprint so tokens without a stored fingerprint aren't treated as stale
    allow(described_class).to receive(:current_scope_fingerprint).and_return('test-fingerprint')
    # Reset in-memory store between examples
    described_class.memory_store.clear
  end

  after do
    FileUtils.rm_rf(tmpdir)
  end

  # ---- load_token ----

  describe '.load_token' do
    context 'when no Vault and no local file exist' do
      it 'returns nil' do
        expect(manager.load_token(:delegated)).to be_nil
      end
    end

    context 'when a valid local file exists' do
      before do
        path = File.join(tmpdir, 'entra_delegated.json')
        File.write(path, JSON.pretty_generate(
                           'access_token'      => 'local-token-abc',
                           'refresh_token'     => 'refresh-xyz',
                           'expires_at'        => (Time.now + 3600).utc.iso8601,
                           'scope_fingerprint' => 'test-fingerprint'
                         ))
      end

      it 'returns the access token from the local file' do
        expect(manager.load_token(:delegated)).to eq('local-token-abc')
      end
    end

    context 'when the local file has an expired token' do
      before do
        path = File.join(tmpdir, 'entra_delegated.json')
        File.write(path, JSON.pretty_generate(
                           'access_token'  => 'expired-token',
                           'refresh_token' => nil,
                           'expires_at'    => (Time.now - 3600).utc.iso8601
                         ))
      end

      it 'returns nil' do
        expect(manager.load_token(:delegated)).to be_nil
      end
    end

    context 'when the local file has no expires_at' do
      before do
        path = File.join(tmpdir, 'entra_delegated.json')
        File.write(path, JSON.pretty_generate(
                           'access_token'      => 'no-expiry-token',
                           'refresh_token'     => nil,
                           'expires_at'        => nil,
                           'scope_fingerprint' => 'test-fingerprint'
                         ))
      end

      it 'returns the token (no expiry check)' do
        expect(manager.load_token(:delegated)).to eq('no-expiry-token')
      end
    end

    context 'when the local file contains invalid JSON' do
      before do
        path = File.join(tmpdir, 'entra_delegated.json')
        File.write(path, 'not-json')
      end

      it 'returns nil' do
        expect(manager.load_token(:delegated)).to be_nil
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

    context 'when a local token is expired but refreshable' do
      before do
        path = File.join(tmpdir, 'entra_delegated.json')
        File.write(path, JSON.pretty_generate(
                           'access_token'      => 'expired-token',
                           'refresh_token'     => 'refresh-token',
                           'expires_at'        => (Time.now - 3600).utc.iso8601,
                           'scopes'            => 'User.Read offline_access',
                           'tenant_id'         => 'tenant-1',
                           'client_id'         => 'client-1',
                           'scope_fingerprint' => 'test-fingerprint'
                         ))

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

    context 'when vault saves token and deletes local file during refresh' do
      before do
        path = File.join(tmpdir, 'entra_delegated.json')
        File.write(path, JSON.pretty_generate(
                           'access_token'      => 'expired-token',
                           'refresh_token'     => 'refresh-token',
                           'expires_at'        => (Time.now - 3600).utc.iso8601,
                           'scopes'            => 'User.Read offline_access',
                           'tenant_id'         => 'tenant-1',
                           'client_id'         => 'client-1',
                           'scope_fingerprint' => 'test-fingerprint'
                         ))

        # Simulate: vault available, save_to_vault succeeds (deletes local), save_to_memory runs
        allow(manager).to receive(:refresh_token) do |qualifier, _data|
          manager.save_to_vault(qualifier, access_token:  'refreshed-via-vault',
                                           refresh_token: 'new-refresh',
                                           expires_at:    Time.now + 3600,
                                           scopes:        'User.Read offline_access',
                                           tenant_id:     'tenant-1',
                                           client_id:     'client-1')
          manager.delete_local(qualifier)
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

      it 'returns the refreshed token from memory even after local file is deleted' do
        token = manager.load_token(:delegated)
        expect(token).to eq('refreshed-via-vault')
        expect(File).not_to exist(File.join(tmpdir, 'entra_delegated.json'))
      end
    end
  end

  # ---- save_token ----

  describe '.save_token' do
    it 'writes the token file to disk when vault is unavailable' do
      manager.save_token(:delegated, access_token: 'save-test', refresh_token: 'refresh',
                                     expires_at: Time.now + 7200)
      path = File.join(tmpdir, 'entra_delegated.json')
      expect(File.exist?(path)).to be true
    end

    it 'sets file permissions to 0600' do
      manager.save_token(:delegated, access_token: 'perm-test', refresh_token: nil,
                                     expires_at: Time.now + 7200)
      path = File.join(tmpdir, 'entra_delegated.json')
      mode = File.stat(path).mode & 0o777
      expect(mode).to eq(0o600)
    end

    it 'writes valid JSON containing the access_token' do
      manager.save_token(:delegated, access_token: 'json-test', refresh_token: 'r',
                                     expires_at: Time.now + 7200)
      path = File.join(tmpdir, 'entra_delegated.json')
      data = JSON.parse(File.read(path))
      expect(data['access_token']).to eq('json-test')
    end

    it 'writes the refresh_token' do
      manager.save_token(:delegated, access_token: 'a', refresh_token: 'my-refresh',
                                     expires_at: Time.now + 7200)
      path = File.join(tmpdir, 'entra_delegated.json')
      data = JSON.parse(File.read(path))
      expect(data['refresh_token']).to eq('my-refresh')
    end

    it 'writes the expires_at as ISO8601' do
      expires = Time.now + 7200
      manager.save_token(:delegated, access_token: 'a', refresh_token: nil, expires_at: expires)
      path = File.join(tmpdir, 'entra_delegated.json')
      data = JSON.parse(File.read(path))
      expect(data['expires_at']).to eq(expires.utc.iso8601)
    end

    it 'persists scopes and client metadata when provided' do
      manager.save_token(:delegated, access_token: 'a', refresh_token: nil, expires_at: Time.now + 7200,
                                     scopes: 'User.Read', tenant_id: 'tenant-1', client_id: 'client-1')
      path = File.join(tmpdir, 'entra_delegated.json')
      data = JSON.parse(File.read(path))
      expect(data).to include('scopes' => 'User.Read', 'tenant_id' => 'tenant-1', 'client_id' => 'client-1')
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

  # ---- bootstrap Vault path (issue #4) ----

  describe 'Vault-only delegated token before canonical identity resolution' do
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
      allow(described_class).to receive(:vault_kv_client).and_return(vault_client)
      allow(described_class).to receive(:settings_auth).and_return(tenant_id: 'tenant-1', client_id: 'client-1')
    end

    it 'derives a canonical-free bootstrap path from tenant and client id' do
      expect(described_class.bootstrap_vault_path(:delegated)).to match(%r{\Abootstrap/entra/delegated/[0-9a-f]{32}/auth\z})
    end

    it 'does not derive a bootstrap path for non-delegated qualifiers' do
      expect(described_class.bootstrap_vault_path(:workload_identity)).to be_nil
    end

    context 'when identity is not yet resolved and the token lives only under the bootstrap key' do
      before do
        allow(described_class).to receive(:canonical_name_available?).and_return(false)
        bootstrap = described_class.bootstrap_vault_path(:delegated)
        allow(vault_client).to receive(:read).and_return(nil)
        allow(vault_client).to receive(:read).with(bootstrap).and_return(double('secret', data: token_body))
      end

      it 'loads the token so identity resolution can proceed' do
        expect(described_class.load_token(:delegated)).to eq('bootstrap-token')
      end
    end

    context 'when saving before identity is resolved' do
      before { allow(described_class).to receive(:canonical_name_available?).and_return(false) }

      it 'writes to the bootstrap key and never to a placeholder canonical path' do
        bootstrap = described_class.bootstrap_vault_path(:delegated)
        allow(vault_client).to receive(:write)

        described_class.save_to_vault(:delegated, access_token: 'boot', refresh_token: 'r',
                                                   expires_at: Time.now + 3600, tenant_id: 'tenant-1',
                                                   client_id: 'client-1')

        expect(vault_client).to have_received(:write).with(bootstrap, hash_including(access_token: 'boot'))
        expect(vault_client).to have_received(:write).once
      end
    end

    context 'when saving after identity resolves' do
      before do
        allow(described_class).to receive(:canonical_name_available?).and_return(true)
        allow(described_class).to receive(:vault_path).with(:delegated).and_return('users/jdoe/entra/delegated/auth')
      end

      it 'writes the canonical key and aliases the bootstrap key' do
        bootstrap = described_class.bootstrap_vault_path(:delegated)
        allow(vault_client).to receive(:write)

        described_class.save_to_vault(:delegated, access_token: 'boot', refresh_token: 'r',
                                                   expires_at: Time.now + 3600, tenant_id: 'tenant-1',
                                                   client_id: 'client-1')

        expect(vault_client).to have_received(:write).with('users/jdoe/entra/delegated/auth', anything)
        expect(vault_client).to have_received(:write).with(bootstrap, anything)
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

  # ---- local_path ----

  describe '.local_path' do
    it 'returns a path under TOKEN_DIR' do
      expected = File.join(tmpdir, 'entra_delegated.json')
      expect(manager.local_path(:delegated)).to eq(expected)
    end

    it 'incorporates the qualifier into the filename' do
      expect(manager.local_path(:privileged)).to end_with('entra_privileged.json')
    end
  end
end
