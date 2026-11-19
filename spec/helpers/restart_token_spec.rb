# frozen_string_literal: true

require 'spec_helper'
require 'open3'
require 'rbconfig'
require 'securerandom'
require_relative '../support/restart_cache_server'

RSpec.describe Legion::Extensions::Identity::Entra::Helpers::TokenManager, 'restart handoff' do
  subject(:manager) { described_class }

  let(:expires_at) { Time.now + 600 }
  let(:auth) { { tenant_id: 'test-tenant', client_id: 'test-client' } }
  let(:namespace) { "entra-test-#{SecureRandom.hex(8)}" }
  let(:redis) { Redis.new(url: @server.url) }
  let(:cache_key) { "#{namespace}:#{manager.cache_namespace}#{manager.restart_cache_key}" }
  let(:token) do
    { access_token: 'test-access', refresh_token: 'test-refresh', expires_at: expires_at,
      scopes: Legion::Extensions::Identity::Entra::Helpers::Scopes.resolve(pattern: :delegated),
      scope_fingerprint: manager.current_scope_fingerprint(:delegated), **auth }
  end

  before(:context) do
    @server = RestartCacheServer.new
    @server.start
  end

  after(:context) { @server.stop }

  around do |example|
    original_identity = Legion::Settings[:identity]
    original_extensions = Legion::Settings[:extensions]
    original_local = Legion::Settings[:cache_local]
    Legion::Settings.set_prop(:identity, { entra: { auth: auth } })
    Legion::Settings.set_prop(:extensions, { identity: { entra: Legion::Extensions::Identity::Entra.default_settings } })
    Legion::Settings.set_prop(:cache_local, Legion::Cache::Settings.local.merge(
                                              driver: 'redis', servers: [@server.url], namespace: namespace
                                            ))
    Legion::Cache::Local.setup
    manager.memory_store.clear
    example.run
  ensure
    redis.scan_each(match: "#{namespace}:*") { |key| redis.del(key) }
    redis.close
    Legion::Cache::Local.reset!
    manager.memory_store.clear
    Legion::Settings.set_prop(:identity, original_identity)
    Legion::Settings.set_prop(:extensions, original_extensions)
    Legion::Settings.set_prop(:cache_local, original_local)
  end

  it 'writes only on actor cancellation, then restores and removes the handoff' do
    manager.save_token(:delegated, **token.except(:scope_fingerprint))
    expect(redis.get(cache_key)).to be_nil

    refresher = Legion::Extensions::Identity::Entra::Delegated::Actor::TokenRefresher.new
    refresher.cancel
    expect(refresher.instance_variable_get(:@timer)).to be_shutdown
    expect(redis.ttl(cache_key)).to be_between(598, 600)

    manager.memory_store.clear
    expect(manager.load_token(:delegated)).to eq('test-access')
    expect(manager.from_memory(:delegated)).to include(refresh_token: 'test-refresh')
    expect(manager.from_memory(:delegated)[:expires_at].to_i).to eq(expires_at.to_i)
    expect(redis.get(cache_key)).to be_nil
  ensure
    refresher&.cancel
  end

  it 'does not retain credentials when the process ends without the shutdown hook' do
    manager.save_to_memory(:delegated, **token)
    manager.memory_store.clear
    expect(manager.token_data(:delegated)).to be_nil
    expect(redis.get(cache_key)).to be_nil
  end

  it 'can disable both shutdown writes and startup restoration through live settings' do
    manager.save_to_memory(:delegated, **token)
    manager.settings[:token][:restart_cache_enabled] = false
    expect(manager.save_restart_token).to be false
    expect(redis.get(cache_key)).to be_nil

    manager.settings[:token][:restart_cache_enabled] = true
    manager.save_restart_token
    manager.memory_store.clear
    manager.settings[:token][:restart_cache_enabled] = false
    expect(manager.restore_restart_token).to be_nil
    expect(redis.get(cache_key)).not_to be_nil
  end

  it 'caps retention with the configured TTL' do
    manager.settings[:token][:restart_cache_ttl] = 120
    manager.save_to_memory(:delegated, **token)
    expect(manager.save_restart_token).to be true
    expect(redis.ttl(cache_key)).to be_between(119, 120)
  end

  it 'never extends the access token lifetime with a larger configured TTL' do
    manager.settings[:token][:restart_cache_ttl] = 7200
    manager.save_to_memory(:delegated, **token)
    manager.save_restart_token
    expect(redis.ttl(cache_key)).to be_between(598, 600)
  end

  [0, -1, 'invalid', Float::INFINITY].each do |ttl|
    it "skips an invalid configured TTL of #{ttl.inspect}" do
      manager.settings[:token][:restart_cache_ttl] = ttl
      manager.save_to_memory(:delegated, **token)
      expect(manager.save_restart_token).to be false
      expect(redis.get(cache_key)).to be_nil
    end
  end

  it 'does not write expired or unknown-expiry tokens with an unlimited TTL' do
    [Time.now - 1, nil].each do |expiry|
      manager.save_to_memory(:delegated, **token, expires_at: expiry)
      expect(manager.save_restart_token).to be false
      expect(redis.get(cache_key)).to be_nil
    end
  end

  it 'rounds a subsecond remaining lifetime down to zero and skips the write' do
    expect(manager.restart_token_ttl(expires_at: Time.now + 0.5)).to eq(0)
  end

  it 'restores a valid access token even without a refresh token' do
    manager.save_to_memory(:delegated, **token, refresh_token: nil)
    manager.save_restart_token
    manager.memory_store.clear
    expect(manager.load_token(:delegated)).to eq('test-access')
    expect(redis.get(cache_key)).to be_nil
  end

  it 'rejects and deletes expired, malformed, and mismatched handoffs' do
    expired = token.merge(expires_at: (Time.now - 1).iso8601)
    malformed = token.merge(expires_at: 'invalid')
    mismatched = token.merge(expires_at: expires_at.iso8601, client_id: 'different-client')
    [expired, malformed, mismatched, { access_token: 'missing-expiry' }].each do |data|
      manager.local_cache_set(manager.restart_cache_key, data, ttl: 600)
      expect(manager.restore_restart_token).to be_nil
      expect(redis.get(cache_key)).to be_nil
    end
  end

  it 'isolates handoffs when the configured tenant or application changes' do
    manager.save_to_memory(:delegated, **token)
    manager.save_restart_token
    manager.memory_store.clear
    Legion::Settings[:identity][:entra][:auth][:client_id] = 'different-client'
    expect(manager.restore_restart_token).to be_nil
    Legion::Settings[:identity][:entra][:auth][:client_id] = 'test-client'
    expect(manager.restore_restart_token[:access_token]).to eq('test-access')
  end

  it 'keeps scope mismatch handling after restoration' do
    manager.save_to_memory(:delegated, **token, scope_fingerprint: 'previous-scopes')
    manager.save_restart_token
    manager.memory_store.clear
    expect(manager.token_data(:delegated, refresh: false)).to be_nil
    expect(manager.from_memory(:delegated)[:scope_fingerprint]).to eq('previous-scopes')
    expect(redis.get(cache_key)).to be_nil
  end

  it 'degrades to the existing authentication flow when Local is unavailable' do
    manager.save_to_memory(:delegated, **token)
    Legion::Cache::Local.shutdown
    expect(manager.save_restart_token).to be false
    manager.memory_store.clear
    expect(manager.token_data(:delegated)).to be_nil
  end

  it 'hands off across separate Ruby processes and is absent for a third process' do
    script = <<~RUBY
      require 'rspec'
      require 'spec_helper'
      url, namespace, mode = ARGV
      auth = { tenant_id: 'test-tenant', client_id: 'test-client' }
      Legion::Settings.set_prop(:identity, { entra: { auth: auth } })
      Legion::Settings.set_prop(:cache_local, Legion::Cache::Settings.local.merge(
        driver: 'redis', servers: [url], namespace: namespace
      ))
      Legion::Cache::Local.setup
      manager = Legion::Extensions::Identity::Entra::Helpers::TokenManager
      if mode == 'write'
        require 'legion/extensions/builders/helpers'
        builder = Object.new.extend(Legion::Extensions::Builder::Helpers)
        builder.define_singleton_method(:helper_files) do
          Dir[File.expand_path('lib/legion/extensions/identity/entra/helpers/*.rb')]
        end
        builder.build_helpers
        manager.save_to_memory(:delegated, access_token: 'process-access', refresh_token: 'process-refresh',
          expires_at: Time.now + 600, scope_fingerprint: manager.current_scope_fingerprint(:delegated), **auth)
        actor = Legion::Extensions::Identity::Entra::Delegated::Actor::TokenRefresher.new
        actor.cancel
      else
        data = manager.token_data(:delegated, refresh: false)
        expected = mode == 'read' ? 'process-access' : nil
        raise 'Unexpected restored token' unless data&.dig(:access_token) == expected
        raise 'Refresh credential missing' if mode == 'read' && data[:refresh_token] != 'process-refresh'
      end
      Legion::Cache::Local.shutdown
    RUBY
    %w[write read consumed].each do |mode|
      output, error, status = Open3.capture3(RbConfig.ruby, '-Ilib', '-Ispec', '-e', script, @server.url, namespace, mode)
      expect(status.success?).to be(true), "#{mode} process failed: #{error}\n#{output}"
    end
  end
end
