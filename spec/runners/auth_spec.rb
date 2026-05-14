# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Legion::Extensions::Identity::Entra::Delegated::Runners::Login do
  subject(:runner) { Object.new.extend(described_class) }

  describe '#authorize_url' do
    it 'builds a Microsoft identity authorization URL with PKCE parameters' do
      url = runner.authorize_url(
        tenant_id:      'tenant-1',
        client_id:      'client-1',
        redirect_uri:   'http://127.0.0.1/callback',
        scope:          'openid profile User.Read',
        state:          'csrf-state',
        code_challenge: 'challenge'
      )

      expect(url).to start_with('https://login.microsoftonline.com/tenant-1/oauth2/v2.0/authorize?')
      expect(url).to include('response_type=code')
      expect(url).to include('client_id=client-1')
      expect(url).to include('code_challenge=challenge')
      expect(url).to include('code_challenge_method=S256')
    end
  end

  describe '#request_device_code' do
    it 'requests a device code with delegated scopes' do
      expect(runner).to receive(:oauth_post).with(
        'tenant-1',
        'oauth2/v2.0/devicecode',
        client_id: 'client-1',
        scope:     'User.Read offline_access'
      ).and_return(device_code: 'device-1')

      expect(runner.request_device_code(tenant_id: 'tenant-1', client_id: 'client-1',
                                        scope: 'User.Read offline_access')).to eq(
                                          result: { device_code: 'device-1' }
                                        )
    end
  end

  describe '#poll_device_code' do
    it 'polls until Microsoft returns an access token' do
      allow(runner).to receive(:sleep)
      allow(runner).to receive(:oauth_post).and_return(
        { error: 'authorization_pending' },
        { access_token: 'delegated-token' }
      )

      expect(runner.poll_device_code(tenant_id: 'tenant-1', client_id: 'client-1',
                                     device_code: 'device-1', interval: 0)).to eq(
                                       result: { access_token: 'delegated-token' }
                                     )
    end
  end

  describe '#refresh_delegated_token' do
    it 'uses the refresh_token grant' do
      expect(runner).to receive(:oauth_post).with(
        'tenant-1',
        'oauth2/v2.0/token',
        grant_type:    'refresh_token',
        client_id:     'client-1',
        refresh_token: 'refresh-1',
        scope:         'User.Read offline_access'
      ).and_return(access_token: 'refreshed-token')

      expect(runner.refresh_delegated_token(tenant_id: 'tenant-1', client_id: 'client-1',
                                            refresh_token: 'refresh-1',
                                            scope: 'User.Read offline_access')).to eq(
                                              result: { access_token: 'refreshed-token' }
                                            )
    end
  end
end

RSpec.describe Legion::Extensions::Identity::Entra::Application::Runners::Credential do
  subject(:runner) { Object.new.extend(described_class) }

  describe '#acquire_token' do
    it 'requests a client_credentials token from Microsoft identity' do
      expect(runner).to receive(:credential_post).with(
        'tenant-1',
        grant_type:    'client_credentials',
        client_id:     'client-1',
        client_secret: 'secret',
        scope:         'https://graph.microsoft.com/.default'
      ).and_return(access_token: 'app-token')

      expect(runner.acquire_token(tenant_id: 'tenant-1', client_id: 'client-1',
                                  client_secret: 'secret')).to eq(
                                    result: { access_token: 'app-token' }
                                  )
    end
  end
end
