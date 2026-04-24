# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe Legion::Extensions::Identity::Entra::Helpers::TokenManager do
  subject(:manager) { described_class }

  let(:tmpdir) { Dir.mktmpdir('entra-tokens') }

  before do
    stub_const('Legion::Extensions::Identity::Entra::Helpers::TokenManager::TOKEN_DIR', tmpdir)
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
                           'access_token'  => 'local-token-abc',
                           'refresh_token' => 'refresh-xyz',
                           'expires_at'    => (Time.now + 3600).utc.iso8601
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
                           'access_token'  => 'no-expiry-token',
                           'refresh_token' => nil,
                           'expires_at'    => nil
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
  end

  # ---- save_token ----

  describe '.save_token' do
    it 'writes the token file to disk' do
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
  end

  # ---- vault_available? ----

  describe '.vault_available?' do
    context 'when Legion::Crypt is not defined' do
      before { hide_const('Legion::Crypt') }

      it 'returns falsey' do
        expect(manager.vault_available?).to be_falsey
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

    context 'when Legion::Crypt.vault_connected? returns true' do
      before do
        crypt = Module.new { def self.vault_connected? = true }
        stub_const('Legion::Crypt', crypt)
      end

      it 'returns true' do
        expect(manager.vault_available?).to be true
      end
    end
  end

  # ---- vault_path ----

  describe '.vault_path' do
    context 'when Legion::Identity::Process is not defined' do
      before { hide_const('Legion::Identity') }

      it 'uses default as the identity segment' do
        expect(manager.vault_path(:delegated)).to eq('users/default/entra_delegated')
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
