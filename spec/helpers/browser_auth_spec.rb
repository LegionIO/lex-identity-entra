# frozen_string_literal: true

require 'spec_helper'
require 'legion/extensions/identity/entra/helpers/browser_auth'

RSpec.describe Legion::Extensions::Identity::Entra::Helpers::BrowserAuth do
  subject(:browser_auth) { described_class.new(tenant_id: 'tenant-1', client_id: 'client-1', auth: auth) }

  let(:auth) do
    double(
      'auth',
      request_device_code: { result: { verification_uri: 'https://microsoft.com/devicelogin',
                                       user_code:        'ABCD-EFGH',
                                       device_code:      'device-1' } },
      poll_device_code:    { result: { access_token: 'delegated-token' } },
      authorize_url:       'https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize'
    )
  end

  describe '#generate_pkce' do
    it 'returns a verifier and S256 challenge' do
      verifier, challenge = browser_auth.generate_pkce

      expect(verifier).to be_a(String)
      expect(challenge).to be_a(String)
      expect(challenge).not_to eq(verifier)
    end
  end

  describe '#authenticate' do
    it 'uses device code auth when no GUI is available' do
      allow(browser_auth).to receive(:gui_available?).and_return(false)

      expect(browser_auth.authenticate).to eq(result: { access_token: 'delegated-token' })
      expect(auth).to have_received(:request_device_code).with(
        tenant_id: 'tenant-1',
        client_id: 'client-1',
        scope:     described_class.default_scopes
      )
      expect(auth).to have_received(:poll_device_code).with(
        tenant_id:   'tenant-1',
        client_id:   'client-1',
        device_code: 'device-1'
      )
    end

    it 'falls back to device code auth when browser launch fails' do
      allow(browser_auth).to receive(:gui_available?).and_return(true)
      allow(browser_auth).to receive(:open_browser).and_return(false)

      expect(browser_auth.authenticate).to eq(result: { access_token: 'delegated-token' })
    end
  end
end
