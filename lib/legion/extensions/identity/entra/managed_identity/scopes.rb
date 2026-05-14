# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module ManagedIdentity
          module Scopes
            CATEGORIES = {
              microsoft_graph: %w[
                User.Read.All
                Application.Read.All
                Directory.Read.All
                Group.Read.All
                Mail.Read
                Sites.Read.All
                Files.Read.All
              ]
            }.freeze
          end
        end
      end
    end
  end
end
