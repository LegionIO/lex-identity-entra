# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Legion::Extensions::Identity::Entra::Helpers::AccountDiscovery do
  subject(:discovery) { described_class }

  let(:token_manager) { Legion::Extensions::Identity::Entra::Helpers::TokenManager }
  let(:graph_client) { Legion::Extensions::Identity::Entra::Helpers::GraphClient }

  describe '.resolve_all_accounts' do
    before do
      allow(discovery).to receive(:discovered_qualifiers).and_return(%i[delegated adm_jdoe])
      allow(token_manager).to receive(:load_token).with(:delegated).and_return('primary-token')
      allow(token_manager).to receive(:load_token).with(:adm_jdoe).and_return('priv-token')
      allow(graph_client).to receive(:fetch_me).with('primary-token').and_return(
        id: 'id-1', display_name: 'Jane Doe', mail: 'jdoe@example.com',
        employee_id: 'E123', on_premises_sam_account_name: 'jdoe',
        mail_nickname: 'jdoe'
      )
      allow(graph_client).to receive(:fetch_me).with('priv-token').and_return(
        id: 'id-2', display_name: 'Jane Doe Admin', mail: 'adm-jdoe@example.com',
        employee_id: 'E123', on_premises_sam_account_name: 'adm-jdoe',
        mail_nickname: 'adm-jdoe'
      )
    end

    it 'resolves every discovered qualifier into an identity hash' do
      expect(discovery.resolve_all_accounts.length).to eq(2)
    end

    it 'marks the delegated account as primary' do
      expect(discovery.resolve_all_accounts.first[:account_type]).to eq('primary')
    end

    it 'marks admin-pattern accounts as privileged' do
      expect(discovery.resolve_all_accounts.last[:account_type]).to eq('privileged')
    end

    it 'preserves the account qualifier' do
      expect(discovery.resolve_all_accounts.map { |entry| entry[:qualifier] }).to eq(%i[delegated adm_jdoe])
    end
  end
end
