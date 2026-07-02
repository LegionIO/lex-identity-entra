# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Legion::Extensions::Identity::Entra::Delegated::Actor::AuthValidator do
  subject(:validator) { described_class.allocate }

  let(:identity_module) { Legion::Extensions::Identity::Entra::Delegated::Identity }
  let(:lease) { double('lease') }
  let(:broker) { double('broker') }

  before do
    stub_const('Legion::Identity::Broker', broker)
    # `log` is mixed into actors by the Legion runtime, which isn't booted here.
    validator.define_singleton_method(:log) { Logger.new(File::NULL) }
    allow(identity_module).to receive(:provide_token).with(qualifier: :delegated).and_return(lease)
    allow(broker).to receive(:register_provider)
  end

  describe '#register_broker' do
    it 'registers the delegated provider under :entra_delegated with the delegated qualifier' do
      # This is the provider-name contract the token manager relies on for
      # Broker fallback (issue #5). Registration and TokenManager.from_broker
      # must use the same provider name (:entra_delegated) or the lookup misses.
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
end
