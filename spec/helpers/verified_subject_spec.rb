# frozen_string_literal: true

require 'spec_helper'
require 'base64'
require 'faraday'

RSpec.describe Legion::Extensions::Identity::Entra::Delegated::Identity, 'verified Graph subjects' do
  let(:tenant) { '11111111-1111-1111-1111-111111111111' }
  let(:oid) { '22222222-2222-2222-2222-222222222222' }
  let(:claims) { { tid: tenant, oid: oid } }
  let(:token) { "e30.#{Base64.urlsafe_encode64(Legion::JSON.dump(claims), padding: false)}.fixture-signature" }
  let(:status) { 200 }
  let(:profile) { { id: oid, displayName: 'Jeff Smith', mailNickname: 'jeff' } }
  let(:graph) { Legion::Extensions::Identity::Entra::Helpers::GraphClient }
  let(:tokens) { Legion::Extensions::Identity::Entra::Helpers::TokenManager }

  before do
    connection = Faraday.new(url: 'https://graph.microsoft.com/v1.0/') do |faraday|
      faraday.adapter :test do |stub|
        stub.get(%r{/me}) { [status, { 'Content-Type' => 'application/json' }, Legion::JSON.dump(profile)] }
      end
    end
    allow(graph).to receive(:graph_connection).and_return(connection)
    allow(tokens).to receive(:load_token).with(:delegated) { token }
  end

  it 'resolves the tenant/object subject accepted by Graph, independent of the human account name' do
    first = described_class.resolve
    profile[:mailNickname] = 'jeff-renamed'
    second = described_class.resolve

    expect(first[:provider_identity]).to eq("#{tenant}:#{oid}")
    expect(second[:provider_identity]).to eq(first[:provider_identity])
    expect(second[:canonical_name]).to eq('jeff-renamed')
  end

  it 'does not merge matching names or object IDs across tenants' do
    first = described_class.resolve
    other_tenant = '33333333-3333-3333-3333-333333333333'
    other_token = "e30.#{Base64.urlsafe_encode64(Legion::JSON.dump(tid: other_tenant, oid: oid), padding: false)}.fixture-signature"
    allow(tokens).to receive(:load_token).with(:delegated).and_return(other_token)

    second = described_class.resolve

    expect(second[:canonical_name]).to eq(first[:canonical_name])
    expect(second[:provider_identity]).to eq("#{other_tenant}:#{oid}")
    expect(second[:provider_identity]).not_to eq(first[:provider_identity])
  end

  context 'when Graph rejects the bearer token' do
    let(:status) { 401 }

    it 'does not accept tenant claims from the rejected token' do
      expect(described_class.resolve).to be_nil
    end
  end

  context 'when /me and the accepted token disagree about the object' do
    let(:profile) { { id: '44444444-4444-4444-4444-444444444444', mailNickname: 'jeff' } }

    it 'refuses to authenticate the mismatched subject' do
      expect(described_class.resolve).to be_nil
    end
  end

  context 'when the token has no tenant claim' do
    let(:claims) { { oid: oid } }

    it 'does not infer a tenant from mutable names or local configuration' do
      expect(described_class.resolve).to be_nil
    end
  end

  context 'when Graph accepts an opaque token' do
    let(:token) { 'opaque-accepted-bearer' }

    it 'keeps the profile usable without fabricating a shared authenticated identity' do
      expect(graph.fetch_me(token)[:id]).to eq(oid)
      expect(described_class.resolve).to be_nil
    end
  end
end
