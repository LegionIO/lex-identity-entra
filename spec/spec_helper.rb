# frozen_string_literal: true

require 'simplecov'
SimpleCov.start do
  add_filter '/spec/'
end

require 'bundler/setup'
require 'legion/crypt'
require 'legion/json'
require 'legion/json/helper'
require 'legion/logging'
require 'legion/logging/helper'
require 'legion/settings'
require 'legion/settings/helper'

# Stub Legion::Extensions::Actors and Legion::Extensions::Hooks before loading
# extension files that inherit from them — these base classes live in the
# LegionIO monorepo core gems which are not available in this isolated test env.
module Legion
  module Extensions
    module Actors
      class Base
        def run; end
      end

      class Once < Base; end
      class Every < Base; end
    end

    module Hooks
      class Base
        def self.mount(_path); end
      end
    end

    module Helpers
      module Lex
        include Legion::Logging::Helper if defined?(Legion::Logging::Helper)
        include Legion::Settings::Helper if defined?(Legion::Settings::Helper)
        include Legion::JSON::Helper if defined?(Legion::JSON::Helper)

        def self.included(base)
          base.extend base if base.instance_of?(Module)
        end
      end
    end
  end
end

require 'legion/extensions/identity/entra'
require 'tmpdir'

ENTRA_SPEC_RUN_DIR = Dir.mktmpdir('lex-identity-entra-run')
at_exit { FileUtils.rm_rf(ENTRA_SPEC_RUN_DIR) }

RSpec.configure do |config|
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end
  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  # Keep InteractiveAuthGuard lock/state files out of the real ~/.legionio and
  # start every example with a clean guard + refresh negative cache.
  config.before do
    guard = Legion::Extensions::Identity::Entra::Helpers::InteractiveAuthGuard
    FileUtils.rm_f(Dir.glob(File.join(ENTRA_SPEC_RUN_DIR, '*')))
    allow(guard).to receive_messages(lock_path:  File.join(ENTRA_SPEC_RUN_DIR, 'auth.lock'),
                                     state_path: File.join(ENTRA_SPEC_RUN_DIR, 'auth_state.json'),
                                     screen_locked?: false, idle_seconds: nil)
    guard.reload!
    Legion::Extensions::Identity::Entra::Helpers::TokenManager.refresh_failures.clear
  end
end
