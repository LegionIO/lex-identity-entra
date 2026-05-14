# frozen_string_literal: true

require_relative 'lib/legion/extensions/identity/entra/version'

Gem::Specification.new do |spec|
  spec.name          = 'lex-identity-entra'
  spec.version       = Legion::Extensions::Identity::Entra::VERSION
  spec.authors       = ['Esity']
  spec.email         = ['matthewdiverson@gmail.com']

  spec.summary       = 'LEX Identity: Entra ID (Azure AD) provider'
  spec.description   = 'LegionIO identity provider that resolves Entra ID (Azure AD) identity ' \
                       'via Microsoft Graph API into the unified identity contract'
  spec.homepage      = 'https://github.com/LegionIO/lex-identity-entra'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>= 3.4'

  spec.metadata['homepage_uri']          = spec.homepage
  spec.metadata['source_code_uri']       = 'https://github.com/LegionIO/lex-identity-entra'
  spec.metadata['documentation_uri']     = 'https://github.com/LegionIO/lex-identity-entra'
  spec.metadata['changelog_uri']         = 'https://github.com/LegionIO/lex-identity-entra'
  spec.metadata['bug_tracker_uri']       = 'https://github.com/LegionIO/lex-identity-entra/issues'
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.require_paths = ['lib']

  # Core framework dependencies
  spec.add_dependency 'concurrent-ruby', '>= 1.2'
  spec.add_dependency 'faraday',         '>= 2.0'
  spec.add_dependency 'legion-json',     '>= 1.2.1'
  spec.add_dependency 'legion-settings', '>= 1.3.14'

  # Optional runtime dependencies are guarded with defined?() in the source:
  #   legion-crypt — for Vault token persistence (Legion::Crypt.vault_read / vault_write)
end
