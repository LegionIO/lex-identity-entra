# frozen_string_literal: true

require 'spec_helper'

# Legion::Identity::Lease lives in the legionio gem (not a dependency of this extension).
# Require it if available, otherwise define a minimal version for spec assertions.
begin
  require 'legion/identity/lease'
rescue LoadError
  module Legion
    module Identity
      class Lease
        attr_reader :provider, :credential, :lease_id, :expires_at, :renewable, :issued_at, :metadata

        def initialize(provider:, credential:, lease_id: nil, expires_at: nil, renewable: false,
                       issued_at: nil, metadata: {})
          @provider   = provider
          @credential = credential
          @lease_id   = lease_id
          @expires_at = expires_at
          @renewable  = renewable
          @issued_at  = issued_at || Time.now
          @metadata   = metadata.freeze
        end

        def valid?
          !credential.nil? && !expired?
        end

        def expired?
          return false if expires_at.nil?

          Time.now >= expires_at
        end
      end
    end
  end
end

RSpec.describe Legion::Extensions::Identity::Entra::Delegated::Identity do
  subject(:identity) { described_class }

  let(:graph_client) { Legion::Extensions::Identity::Entra::Helpers::GraphClient }
  let(:token_manager) { Legion::Extensions::Identity::Entra::Helpers::TokenManager }

  # ---- Provider contract interface ----

  describe '.provider_name' do
    it 'returns :entra_delegated' do
      expect(identity.provider_name).to eq(:entra_delegated)
    end
  end

  describe '.provider_type' do
    it 'returns :auth' do
      expect(identity.provider_type).to eq(:auth)
    end
  end

  describe '.priority' do
    it 'returns 100' do
      expect(identity.priority).to eq(100)
    end
  end

  describe '.trust_weight' do
    it 'returns 40' do
      expect(identity.trust_weight).to eq(40)
    end
  end

  describe '.trust_level' do
    it 'returns :verified' do
      expect(identity.trust_level).to eq(:verified)
    end
  end

  describe '.capabilities' do
    it 'includes :authenticate, :profile, :interactive, :outbound_auth' do
      expect(identity.capabilities).to include(:authenticate, :profile, :interactive, :outbound_auth)
    end
  end

  # ---- normalize ----

  describe '.normalize' do
    it 'strips @domain and downcases' do
      expect(identity.normalize('jdoe@example.com')).to eq('jdoe')
    end

    it 'downcases a name without domain' do
      expect(identity.normalize('JDOE')).to eq('jdoe')
    end

    it 'strips leading and trailing whitespace' do
      expect(identity.normalize('  jdoe  ')).to eq('jdoe')
    end

    it 'removes special characters (dots)' do
      expect(identity.normalize('user.name@example.com')).to eq('username')
    end

    it 'preserves hyphens and underscores' do
      expect(identity.normalize('user_name-ok@example.com')).to eq('user_name-ok')
    end

    it 'handles nil-like values via to_s' do
      expect(identity.normalize(nil)).to eq('')
    end

    it 'handles symbol input' do
      expect(identity.normalize(:alice)).to eq('alice')
    end
  end

  # ---- resolve ----

  describe '.resolve' do
    context 'when no cached token exists' do
      before do
        allow(token_manager).to receive(:load_token).with(:delegated).and_return(nil)
      end

      it 'returns nil' do
        expect(identity.resolve).to be_nil
      end
    end

    context 'when token exists but Graph API fails' do
      before do
        allow(token_manager).to receive(:load_token).with(:delegated).and_return('fake-token')
        allow(graph_client).to receive(:fetch_me).with('fake-token').and_return(nil)
      end

      it 'returns nil' do
        expect(identity.resolve).to be_nil
      end
    end

    context 'when Graph API returns a profile without canonical name fields' do
      before do
        allow(token_manager).to receive(:load_token).with(:delegated).and_return('fake-token')
        allow(graph_client).to receive(:fetch_me).with('fake-token').and_return(
          id: 'abc-123', display_name: 'Test User', mail: 'test@example.com',
          on_premises_sam_account_name: nil, mail_nickname: nil
        )
      end

      it 'returns nil' do
        expect(identity.resolve).to be_nil
      end
    end

    context 'when Graph API returns a valid profile with onPremisesSamAccountName' do
      let(:profile) do
        {
          id:                           'abc-123',
          display_name:                 'Jane Doe',
          mail:                         'jdoe@example.com',
          employee_id:                  'E12345',
          on_premises_sam_account_name: 'jdoe',
          on_premises_domain_name:      'MS',
          mail_nickname:                'jdoe',
          department:                   'Engineering',
          job_title:                    'Engineer',
          company_name:                 'ExampleCorp'
        }
      end

      before do
        allow(token_manager).to receive(:load_token).with(:delegated).and_return('real-token')
        allow(graph_client).to receive(:fetch_me).with('real-token').and_return(profile)
      end

      it 'returns an identity hash' do
        expect(identity.resolve).to be_a(Hash)
      end

      it 'sets canonical_name to the normalized sAMAccountName' do
        expect(identity.resolve[:canonical_name]).to eq('jdoe')
      end

      it 'sets kind to :human' do
        expect(identity.resolve[:kind]).to eq(:human)
      end

      it 'sets source to :entra_delegated' do
        expect(identity.resolve[:source]).to eq(:entra_delegated)
      end

      it 'sets provider_identity to the Entra object ID' do
        expect(identity.resolve[:provider_identity]).to eq('abc-123')
      end

      it 'sets employee_id from the profile' do
        expect(identity.resolve[:employee_id]).to eq('E12345')
      end

      it 'includes the full profile' do
        expect(identity.resolve[:profile]).to eq(profile)
      end
    end

    context 'when onPremisesSamAccountName is nil but mailNickname is present' do
      let(:profile) do
        {
          id:                           'def-456',
          display_name:                 'Cloud User',
          mail:                         'cloud@example.com',
          employee_id:                  nil,
          on_premises_sam_account_name: nil,
          on_premises_domain_name:      nil,
          mail_nickname:                'clouduser',
          department:                   nil,
          job_title:                    nil,
          company_name:                 nil
        }
      end

      before do
        allow(token_manager).to receive(:load_token).with(:delegated).and_return('token')
        allow(graph_client).to receive(:fetch_me).with('token').and_return(profile)
      end

      it 'falls back to mail_nickname for canonical_name' do
        expect(identity.resolve[:canonical_name]).to eq('clouduser')
      end
    end
  end

  # ---- resolve_all ----

  describe '.resolve_all' do
    let(:account_discovery) { Legion::Extensions::Identity::Entra::Helpers::AccountDiscovery }

    context 'when account discovery returns resolved accounts' do
      before do
        allow(account_discovery).to receive(:resolve_all_accounts).and_return([
                                                                                { canonical_name: 'jdoe',
                                                                                  source:         :entra }
                                                                              ])
      end

      it 'returns all discovered Entra accounts' do
        expect(identity.resolve_all).to eq([{ canonical_name: 'jdoe', source: :entra }])
      end
    end

    context 'when resolve returns nil' do
      before do
        allow(account_discovery).to receive(:resolve_all_accounts).and_return([])
        allow(token_manager).to receive(:load_token).with(:delegated).and_return(nil)
      end

      it 'returns an empty array' do
        expect(identity.resolve_all).to eq([])
      end
    end

    context 'when resolve returns a result' do
      before do
        allow(account_discovery).to receive(:resolve_all_accounts).and_return([])
        allow(token_manager).to receive(:load_token).with(:delegated).and_return('token')
        allow(graph_client).to receive(:fetch_me).with('token').and_return(
          id: 'abc', on_premises_sam_account_name: 'user1', mail_nickname: 'user1',
          display_name: 'User', mail: 'u@x.com', employee_id: nil,
          on_premises_domain_name: nil, department: nil, job_title: nil, company_name: nil
        )
      end

      it 'returns a single-element array' do
        expect(identity.resolve_all.length).to eq(1)
      end
    end
  end

  # ---- provide_token ----

  describe '.provide_token' do
    context 'when no cached token exists' do
      before do
        allow(token_manager).to receive(:load_token).with(:delegated).and_return(nil)
      end

      it 'returns nil' do
        expect(identity.provide_token).to be_nil
      end
    end

    context 'when a cached token exists' do
      before do
        allow(token_manager).to receive(:load_token).with(:delegated).and_return('my-access-token')
        allow(token_manager).to receive(:token_data).with(:delegated, refresh: false).and_return(
          {
            access_token:  'my-access-token',
            refresh_token: 'my-refresh-token',
            expires_at:    Time.now + 3600,
            scopes:        'openid profile User.Read offline_access'
          }
        )
      end

      it 'returns a Legion::Identity::Lease' do
        result = identity.provide_token
        expect(result).to be_a(Legion::Identity::Lease)
      end

      it 'sets provider to :entra_delegated' do
        expect(identity.provide_token.provider).to eq(:entra_delegated)
      end

      it 'sets credential to the token string' do
        expect(identity.provide_token.credential).to eq('my-access-token')
      end

      it 'sets renewable to true' do
        expect(identity.provide_token.renewable).to be true
      end

      it 'sets expires_at approximately 1 hour from now' do
        result = identity.provide_token
        expect(result.expires_at).to be_within(5).of(Time.now + 3600)
      end

      it 'reports as valid' do
        expect(identity.provide_token.valid?).to be true
      end
    end
  end
end
