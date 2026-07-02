# frozen_string_literal: true

require 'spec_helper'

# Issue #1 — opt-in :mail delegated scope category (Mail.Read + Mail.Send only).
RSpec.describe Legion::Extensions::Identity::Entra::Delegated::Scopes do
  let(:categories) { described_class::CATEGORIES }
  let(:scopes) { Legion::Extensions::Identity::Entra::Helpers::Scopes }

  describe 'CATEGORIES[:mail]' do
    it 'resolves to exactly Mail.Read + Mail.Send (set equality — least privilege)' do
      expect(categories[:mail]).to contain_exactly('Mail.Read', 'Mail.Send')
    end

    it 'does not include over-scope grants (ReadWrite / MailboxSettings / Read.Shared)' do
      expect(categories[:mail]).not_to include(
        'Mail.ReadWrite', 'MailboxSettings.Read', 'Mail.Read.Shared'
      )
    end

    it 'is NOT a member of the default-enabled :microsoft_graph category (no silent grant)' do
      expect(categories[:microsoft_graph]).not_to include('Mail.Read', 'Mail.Send')
    end
  end

  describe '.resolve regression + opt-in' do
    # Drive enabled_categories directly via the settings-backed helper.
    def resolve_with(enabled)
      allow(scopes).to receive(:setting).and_call_original
      allow(scopes).to receive(:setting).with(:delegated, :enabled_categories).and_return(enabled)
      scopes.resolve(pattern: :delegated)
    end

    def fingerprint(resolved)
      Digest::MD5.hexdigest(resolved.split.sort.join(' '))
    end

    it 'with :mail NOT enabled, produces no Mail.* and an unchanged fingerprint' do
      resolved = resolve_with(['microsoft_graph'])
      expect(resolved).not_to match(/Mail\./)
    end

    it 'with :mail enabled, contains Mail.Read + Mail.Send' do
      resolved = resolve_with(%w[microsoft_graph mail])
      expect(resolved).to include('Mail.Read', 'Mail.Send')
    end

    it 'enabling :mail changes the delegated scope_fingerprint (forces one-time re-consent)' do
      without_mail = fingerprint(resolve_with(['microsoft_graph']))
      with_mail    = fingerprint(resolve_with(%w[microsoft_graph mail]))
      expect(with_mail).not_to eq(without_mail)
    end
  end
end
