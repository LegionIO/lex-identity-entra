# frozen_string_literal: true

module Legion
  module Extensions
    module Identity
      module Entra
        module Delegated
          module Scopes
            CATEGORIES = {
              microsoft_graph:              %w[
                User.Read
                email
                openid
                profile
                offline_access
                Device.Read
                Files.Read
                Files.Read.All
                Files.ReadWrite.Selected
                ShortNotes.Read
                CallAiInsights.Read.All
                CallEvents.Read
                CallRecordings.Read.All
                CallTranscripts.Read.All
                Channel.ReadBasic.All
              ],
              # Opt-in mailbox access for the signed-in user (lex-outlook, ADR-0005).
              # Least privilege: Mail.Read + Mail.Send ONLY. Deliberately excludes
              # Mail.ReadWrite (create/update/delete/move), MailboxSettings.Read
              # (auto-reply/timezone/working-hours), and Mail.Read.Shared — no v1
              # lex-outlook runner needs them, so they are deferred to a later
              # fingerprint-changing edit when a runner actually requires them.
              #
              # NOT a member of :microsoft_graph, so existing delegated/Teams
              # installs see no scope change and no forced re-consent. Enabling
              # :mail in identity.entra.delegated.scopes.enabled_categories changes
              # the delegated scope_fingerprint and forces a one-time re-consent for
              # that qualifier — expected behavior, not an error (see README).
              mail:                         %w[
                Mail.Read
                Mail.Send
              ],
              teams:                        %w[
                Chat.Create
                Chat.Read
                Chat.ReadBasic
                Chat.ReadWrite
                ChatMember.Read
                ChatMessage.Read
                ChatMessage.Send
                Channel.ReadBasic.All
                ChannelMember.Read.All
                ChannelMessage.Edit
                ChannelMessage.Read.All
                ChannelMessage.Send
                Team.ReadBasic.All
                Group-Conversation.Read.All
                OnlineMeetings.Read
                OnlineMeetingTranscript.Read.All
                OnlineMeetingRecording.Read.All
                OnlineMeetingArtifact.Read.All
                OnlineMeetingAiInsight.Read.All
                CallAiInsights.Read.All
                CallEvents.Read
                CallRecordings.Read.All
                CallTranscripts.Read.All
                TeamsActivity.Read
                TeamsActivity.Send
                TeamsAppInstallation.ReadForChat
                TeamsAppInstallation.ReadForUser
                TeamsAppInstallation.ReadWriteSelfForUser
                People.Read
                Presence.Read
                Presence.Read.All
              ],
              one_note:                     %w[
                Notes.Create
                Notes.Read
                Notes.Read.All
                Notes.ReadWrite
                Notes.ReadWrite.All
                Notes.ReadWrite.CreatedByApp
              ],
              sharepoint:                   %w[
                AllSites.Read
                EnterpriseResource.Read
                MyFiles.Read
                MyFiles.Write
                Project.Read
                Sites.Selected
                TaskStatus.Submit
              ],
              azure_communication_services: %w[
                Teams.ManageCalls
                Teams.ManageChats
                TeamsExtension.ManageCalls
              ],

              yammer:                       %w[
                access_as_user
                Community.Read.All
                Community.ReadWrite.All
                engage_access
                EngagementConversation.Read.All
                EngagementConversation.ReadWrite.All
                Storyline.ReadWrite.All
                StorylineSettings.Read.All
                user_impersonation
              ]
            }.freeze
          end
        end
      end
    end
  end
end
