# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'

RSpec.describe Legion::Extensions::Identity::Entra::Delegated::Actor::AuthValidator do
  subject(:validator) { described_class.allocate }

  let(:identity_module) { Legion::Extensions::Identity::Entra::Delegated::Identity }
  let(:manager) { Legion::Extensions::Identity::Entra::Helpers::TokenManager }
  let(:lease) { double('lease') }
  let(:broker) { double('broker') }
  let(:tmpdir) { Dir.mktmpdir('entra-tokens') }

  before do
    stub_const('Legion::Identity::Broker', broker)
    stub_const('Legion::Extensions::Identity::Entra::Helpers::TokenManager::TOKEN_DIR', tmpdir)
    allow(Legion::Crypt).to receive(:vault_connected?).and_return(false)
    allow(manager).to receive(:current_scope_fingerprint).and_return('test-fingerprint')
    manager.memory_store.clear
    validator.define_singleton_method(:log) { Logger.new(File::NULL) }
    allow(identity_module).to receive(:provide_token).with(qualifier: :delegated).and_return(lease)
    allow(broker).to receive(:register_provider)
  end

  after do
    FileUtils.rm_rf(tmpdir)
  end

  describe '#register_broker' do
    it 'registers the delegated provider under :entra_delegated with the delegated qualifier' do
      validator.send(:register_broker)

      expect(broker).to have_received(:register_provider).with(
        :entra_delegated,
        provider:  identity_module,
        lease:     lease,
        qualifier: :delegated,
        default:   true
      )
    end

    it 'skips registration when provide_token returns nil' do
      allow(identity_module).to receive(:provide_token).with(qualifier: :delegated).and_return(nil)

      validator.send(:register_broker)

      expect(broker).not_to have_received(:register_provider)
    end
  end

  describe '#manual warns on expired-with-refresh-available (E1)' do
    let(:test_logger) { instance_double(Logger, debug: nil, info: nil, warn: nil, error: nil) }

    before do
      lg = test_logger
      validator.define_singleton_method(:log) { lg }
      allow(manager).to receive(:authenticated?).with(:delegated).and_return(false)
      allow(validator).to receive(:auto_authenticate?).and_return(false)
    end

    context 'when previously authenticated with an expired token that has a refresh_token' do
      before do
        path = File.join(tmpdir, 'entra_delegated.json')
        File.write(path, JSON.pretty_generate(
                           'access_token'      => 'expired-token',
                           'refresh_token'     => 'still-valid-refresh',
                           'expires_at'        => (Time.now - 3600).utc.iso8601,
                           'scopes'            => 'User.Read offline_access',
                           'tenant_id'         => 'tenant-1',
                           'client_id'         => 'client-1',
                           'scope_fingerprint' => 'test-fingerprint'
                         ))
        allow(validator).to receive(:attempt_browser_reauth)
      end

      it 'logs a warning about the refresh dead-end' do
        validator.manual
        expect(test_logger).to have_received(:warn).with(/expired but refresh_token available/)
      end
    end

    context 'when previously authenticated with an expired token that has no refresh_token' do
      before do
        path = File.join(tmpdir, 'entra_delegated.json')
        File.write(path, JSON.pretty_generate(
                           'access_token'      => 'expired-token',
                           'refresh_token'     => nil,
                           'expires_at'        => (Time.now - 3600).utc.iso8601,
                           'scope_fingerprint' => 'test-fingerprint'
                         ))
        allow(validator).to receive(:attempt_browser_reauth)
      end

      it 'does not warn about refresh dead-end' do
        validator.manual
        expect(test_logger).not_to have_received(:warn).with(/expired but refresh_token available/)
      end
    end
  end
end
