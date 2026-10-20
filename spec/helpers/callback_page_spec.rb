# frozen_string_literal: true

require 'spec_helper'
require 'net/http'

RSpec.describe Legion::Extensions::Identity::Entra::Helpers::CallbackPage do
  it 'clearly identifies LegionIO Teams / Entra sign-in success and says the tab can be closed' do
    html = described_class.success_html
    expect(html).to include('LegionIO &mdash; Microsoft Teams / Entra sign-in complete', 'You can close this tab.')
  end

  it 'renders a matching failure page with an escaped reason and the CLI hint' do
    html = described_class.failure_html('access_denied', '<script>x</script>')
    expect(html).to include('LegionIO &mdash; Microsoft Teams / Entra sign-in failed', 'You can close this tab.',
                            'legionio auth teams', 'access_denied', '&lt;script&gt;')
    expect(html).not_to include('<script>x</script>')
  end
end

RSpec.describe Legion::Extensions::Identity::Entra::Helpers::CallbackServer do
  subject(:server) { described_class.new }

  before { server.start }
  after { server.shutdown }

  def get(path)
    Net::HTTP.get_response(URI("http://127.0.0.1:#{server.port}#{path}"))
  end

  it 'serves the success page and captures code/state' do
    response = get('/callback?code=abc&state=xyz')
    expect(response.code).to eq('200')
    expect(response.body).to include('sign-in complete', 'You can close this tab.')
    expect(server.wait_for_callback(timeout: 1)).to eq(code: 'abc', state: 'xyz')
  end

  it 'serves the failure page when Microsoft returns an error' do
    response = get('/callback?error=access_denied&error_description=User+cancelled&state=xyz')
    expect(response.code).to eq('400')
    expect(response.body).to include('sign-in failed', 'access_denied', 'User cancelled')
    expect(server.wait_for_callback(timeout: 1)).to include(error: 'access_denied', state: 'xyz')
  end

  it 'ignores unrelated requests such as /favicon.ico and keeps waiting' do
    expect(get('/favicon.ico').code).to eq('404')
    expect(server.wait_for_callback(timeout: 0.2)).to be_nil
    expect(get('/callback?code=c&state=s').code).to eq('200')
  end
end

RSpec.describe Legion::Extensions::Identity::Entra::Delegated::Runners::Login, '#auth_callback' do
  subject(:runner) { Object.new.extend(described_class) }

  it 'returns the LegionIO success page from the API hook route' do
    result = runner.auth_callback(code: 'c', state: 's')
    expect(result[:result]).to include(authenticated: true)
    expect(result[:response]).to include(status: 200)
    expect(result[:response][:body]).to include('LegionIO &mdash; Microsoft Teams / Entra sign-in complete', 'You can close this tab.')
  end

  it 'returns the failure page when parameters are missing' do
    result = runner.auth_callback
    expect(result[:response]).to include(status: 400)
    expect(result[:response][:body]).to include('sign-in failed', 'missing_params')
  end

  it 'returns the failure page and notifies waiters when Microsoft returns an error' do
    stub_const('Legion::Events', Module.new { def self.emit(*, **); end })
    allow(Legion::Events).to receive(:emit)

    result = runner.auth_callback(error: 'access_denied', error_description: 'denied', state: 's')
    expect(result[:response]).to include(status: 400)
    expect(result[:response][:body]).to include('sign-in failed', 'access_denied')
    expect(Legion::Events).to have_received(:emit)
      .with('identity.entra.oauth.callback', state: 's', error: 'access_denied', error_description: 'denied')
  end
end

RSpec.describe Legion::Extensions::Identity::Entra::Helpers::BrowserAuth, 'guarded authenticate' do
  subject(:browser_auth) do
    described_class.new(tenant_id: 't', client_id: 'c', scopes: 'User.Read', auth: double('auth'), automatic: true)
  end

  let(:guard) { Legion::Extensions::Identity::Entra::Helpers::InteractiveAuthGuard }

  before do
    allow(guard).to receive(:log).and_return(Logger.new(File::NULL))
    allow(browser_auth).to receive(:gui_available?).and_return(true)
  end

  it 'routes through InteractiveAuthGuard with automatic: true' do
    allow(guard).to receive(:run).and_return(error: 'auth_skipped')
    browser_auth.authenticate
    expect(guard).to have_received(:run).with(automatic: true)
  end

  it 'does not open the browser while in backoff after a timeout' do
    allow(browser_auth).to receive(:authenticate_browser).and_return(error: 'timeout')
    browser_auth.authenticate
    browser_auth.authenticate
    expect(browser_auth).to have_received(:authenticate_browser).once
  end

  it 'uses browser_auth.callback_timeout from settings' do
    allow(Legion::Settings).to receive(:dig).and_call_original
    allow(Legion::Settings).to receive(:dig).with(:identity, :entra, :delegated, :browser_auth, :callback_timeout).and_return(30)
    expect(browser_auth.callback_timeout).to eq(30)
  end

  it 'maps a provider error from the callback into an error result' do
    result = browser_auth.send(:exchange_callback, { error: 'access_denied', error_description: 'no' },
                               state: 's', verifier: 'v', callback_uri: 'u')
    expect(result).to eq(error: 'access_denied', description: 'no')
  end
end
