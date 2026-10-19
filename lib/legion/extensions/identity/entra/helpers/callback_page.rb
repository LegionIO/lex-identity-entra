# frozen_string_literal: true

require 'cgi'

module Legion
  module Extensions
    module Identity
      module Entra
        module Helpers
          # HTML returned to the browser by the OAuth redirect (local callback
          # server and the API hook route). Keeps the wording in one place so the
          # user always knows which app the tab belongs to.
          module CallbackPage
            module_function

            TITLE = 'LegionIO &mdash; Microsoft Teams / Entra sign-in'

            def success_html
              render(heading: 'LegionIO &mdash; Microsoft Teams / Entra sign-in complete',
                     message: 'You can close this tab.', color: '#107c10', icon: '&#10004;')
            end

            def failure_html(reason = nil, description = nil)
              detail = [reason, description].compact.map { |v| CGI.escapeHTML(v.to_s) }.reject(&:empty?).join(': ')
              detail_html = detail.empty? ? '' : "<p class=\"detail\">#{detail}</p>"
              render(heading: 'LegionIO &mdash; Microsoft Teams / Entra sign-in failed',
                     message: 'You can close this tab. To try again, run <code>legionio auth teams</code>.',
                     color: '#a4262c', icon: '&#10008;', extra: detail_html)
            end

            def render(heading:, message:, color:, icon:, extra: '')
              <<~HTML
                <!DOCTYPE html>
                <html lang="en"><head><meta charset="utf-8"><title>#{TITLE}</title>
                <style>
                  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;text-align:center;padding:48px;color:#323130}
                  .icon{font-size:48px;color:#{color}} h1{font-size:22px;color:#{color}} .detail{color:#605e5c;font-size:13px}
                  code{background:#f3f2f1;padding:2px 6px;border-radius:3px}
                </style></head>
                <body><div class="icon">#{icon}</div><h1>#{heading}</h1><p>#{message}</p>#{extra}</body></html>
              HTML
            end
          end
        end
      end
    end
  end
end
