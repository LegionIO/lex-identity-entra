# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module Application
          module Scopes
            CATEGORIES = {
              microsoft_graph: %w[
                User.Read.All
                Application.Read.All
                Directory.Read.All
                Group.Read.All
                Mail.Read
                Mail.ReadBasic.All
                Mail.Send
                Calendars.Read
                Sites.Read.All
                Files.Read.All
                TeamMember.Read.All
                Channel.ReadBasic.All
                ChannelMessage.Read.All
                Chat.Read.All
                ChatMessage.Read.All
                OnlineMeetings.Read.All
                OnlineMeetingTranscript.Read.All
                OnlineMeetingRecording.Read.All
                CallRecords.Read.All
              ],
              one_note:        %w[
                Notes.Read.All
                Notes.ReadWrite.All
              ],
              sharepoint:      %w[
                Sites.Read.All
                Sites.ReadWrite.All
                Files.Read.All
                Files.ReadWrite.All
              ]
            }.freeze
          end
        end
      end
    end
  end
end
