# frozen_string_literal: true

require 'spec_helper'
require 'faraday'

RSpec.describe Legion::Extensions::Identity::Entra::Helpers::GraphClient do
  subject(:client) { described_class }

  describe '.fetch_me' do
    let(:access_token) { 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.fake' }
    let(:graph_response_body) do
      {
        'id'                       => 'abc-123-def',
        'displayName'              => 'Matt Iverson',
        'mail'                     => 'matt.iverson@optum.com',
        'employeeId'               => 'E99999',
        'onPremisesSamAccountName' => 'miverso2',
        'onPremisesDomainName'     => 'MS',
        'mailNickname'             => 'matt.iverson',
        'department'               => 'Engineering',
        'jobTitle'                 => 'Senior Engineer',
        'companyName'              => 'Optum'
      }.to_json
    end

    context 'when the Graph API returns 200' do
      before do
        faraday_double = instance_double(Faraday::Connection)
        allow(described_class).to receive(:graph_connection).and_return(faraday_double)

        response = instance_double(Faraday::Response,
                                   success?: true,
                                   status:   200,
                                   body:     graph_response_body)
        allow(faraday_double).to receive(:get).and_return(response)
      end

      it 'returns a hash with symbolized keys' do
        result = client.fetch_me(access_token)
        expect(result).to be_a(Hash)
      end

      it 'maps id correctly' do
        expect(client.fetch_me(access_token)[:id]).to eq('abc-123-def')
      end

      it 'maps displayName to display_name' do
        expect(client.fetch_me(access_token)[:display_name]).to eq('Matt Iverson')
      end

      it 'maps mail correctly' do
        expect(client.fetch_me(access_token)[:mail]).to eq('matt.iverson@optum.com')
      end

      it 'maps employeeId to employee_id' do
        expect(client.fetch_me(access_token)[:employee_id]).to eq('E99999')
      end

      it 'maps onPremisesSamAccountName to on_premises_sam_account_name' do
        expect(client.fetch_me(access_token)[:on_premises_sam_account_name]).to eq('miverso2')
      end

      it 'maps onPremisesDomainName to on_premises_domain_name' do
        expect(client.fetch_me(access_token)[:on_premises_domain_name]).to eq('MS')
      end

      it 'maps mailNickname to mail_nickname' do
        expect(client.fetch_me(access_token)[:mail_nickname]).to eq('matt.iverson')
      end

      it 'maps department correctly' do
        expect(client.fetch_me(access_token)[:department]).to eq('Engineering')
      end

      it 'maps jobTitle to job_title' do
        expect(client.fetch_me(access_token)[:job_title]).to eq('Senior Engineer')
      end

      it 'maps companyName to company_name' do
        expect(client.fetch_me(access_token)[:company_name]).to eq('Optum')
      end
    end

    context 'when the Graph API returns 401' do
      before do
        faraday_double = instance_double(Faraday::Connection)
        allow(described_class).to receive(:graph_connection).and_return(faraday_double)

        response = instance_double(Faraday::Response,
                                   success?: false,
                                   status:   401,
                                   body:     '{"error":"unauthorized"}')
        allow(faraday_double).to receive(:get).and_return(response)
      end

      it 'returns nil' do
        expect(client.fetch_me(access_token)).to be_nil
      end
    end

    context 'when a network error occurs' do
      before do
        faraday_double = instance_double(Faraday::Connection)
        allow(described_class).to receive(:graph_connection).and_return(faraday_double)
        allow(faraday_double).to receive(:get).and_raise(Errno::ECONNREFUSED)
      end

      it 'returns nil' do
        expect(client.fetch_me(access_token)).to be_nil
      end
    end
  end

  describe '.parse_profile' do
    it 'converts camelCase keys to snake_case symbols' do
      data = { 'id' => '1', 'displayName' => 'Test', 'mail' => nil, 'employeeId' => nil,
               'onPremisesSamAccountName' => nil, 'onPremisesDomainName' => nil,
               'mailNickname' => nil, 'department' => nil, 'jobTitle' => nil, 'companyName' => nil }
      result = client.parse_profile(data)
      expect(result.keys).to include(:id, :display_name, :mail, :employee_id,
                                     :on_premises_sam_account_name, :on_premises_domain_name,
                                     :mail_nickname, :department, :job_title, :company_name)
    end
  end
end
