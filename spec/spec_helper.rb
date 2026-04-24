# frozen_string_literal: true

require 'simplecov'
SimpleCov.start do
  add_filter '/spec/'
end

require 'bundler/setup'
require 'legion/logging'
require 'legion/settings'
require 'legion/json/helper'

module Legion
  module Extensions
    module Helpers
      module Lex
        include Legion::Logging::Helper if defined?(Legion::Logging::Helper)
        include Legion::Settings::Helper if defined?(Legion::Settings::Helper)
        include Legion::JSON::Helper if defined?(Legion::JSON::Helper)
      end
    end
  end
end

require 'legion/extensions/identity/entra'

RSpec.configure do |config|
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end
  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end
end
