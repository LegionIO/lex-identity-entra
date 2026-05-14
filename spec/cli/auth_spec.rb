# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Legion::Extensions::Identity::Entra::Delegated::CLI::Auth do
  subject(:cli) { described_class.new }

  describe '.cli_alias' do
    it 'returns entra' do
      expect(described_class.cli_alias).to eq('entra')
    end
  end

  describe '.descriptions' do
    it 'describes login and status commands' do
      expect(described_class.descriptions).to include(:login, :status)
    end
  end

  describe '#login' do
    let(:browser_auth_class) { Legion::Extensions::Identity::Entra::Helpers::BrowserAuth }
    let(:token_manager) { Legion::Extensions::Identity::Entra::Helpers::TokenManager }
    let(:browser_auth) { instance_double(browser_auth_class, authenticate: { result: token_body }) }
    let(:token_body) do
      {
        access_token:  'delegated-token',
        refresh_token: 'refresh-token',
        expires_in:    3600,
        scope:         'openid profile User.Read offline_access'
      }
    end

    before do
      allow(browser_auth_class).to receive(:new).and_return(browser_auth)
      allow(token_manager).to receive(:save_token)
    end

    it 'authenticates and stores the delegated Entra token' do
      # suppress stdout output from puts inside #login
      allow(cli).to receive(:puts)

      cli.login(tenant_id: 'tenant-1', client_id: 'client-1')

      expect(token_manager).to have_received(:save_token).with(
        :delegated,
        access_token:  'delegated-token',
        refresh_token: 'refresh-token',
        expires_in:    3600,
        scopes:        'openid profile User.Read offline_access',
        tenant_id:     'tenant-1',
        client_id:     'client-1'
      )
    end
  end
end
