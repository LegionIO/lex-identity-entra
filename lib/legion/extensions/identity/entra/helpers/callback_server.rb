# frozen_string_literal: true

require 'socket'
require 'uri'
require 'legion/extensions/identity/entra/helpers/callback_page'

module Legion
  module Extensions
    module Identity
      module Entra
        module Helpers
          class CallbackServer
            include Legion::Extensions::Helpers::Lex if Legion::Extensions.const_defined?(:Helpers, false) &&
                                                        Legion::Extensions::Helpers.const_defined?(:Lex, false)

            attr_reader :port

            def initialize
              @server = nil
              @port = nil
              @result = nil
              @mutex = Mutex.new
              @cv = ConditionVariable.new
            end

            def start
              @server = TCPServer.new('127.0.0.1', 0)
              @port = @server.addr[1]
              @thread = Thread.new { listen } # rubocop:disable ThreadSafety/NewThread
            end

            def wait_for_callback(timeout: 120)
              @mutex.synchronize do
                @cv.wait(@mutex, timeout) unless @result
                @result
              end
            end

            def shutdown
              @server&.close
              @thread&.join(2)
              @thread&.kill
            rescue IOError => e
              log.debug("shutdown ignored closed server: #{e.message}")
              nil
            end

            def redirect_uri
              "http://127.0.0.1:#{@port}/callback"
            end

            private

            def listen
              until @result
                client = @server.accept
                request_line = client.gets
                drain_headers(client)
                status, body = handle_request(request_line)
                client.print "HTTP/1.1 #{status}\r\nContent-Type: text/html; charset=utf-8\r\n" \
                             "Content-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}"
                client.close
              end
            rescue IOError # rubocop:disable Legion/RescueLogging/NoCapture
              nil
            rescue StandardError => e
              @mutex.synchronize do
                @result ||= { error: e.message }
                @cv.broadcast
              end
            end

            def drain_headers(client)
              line = client.gets
              line = client.gets until line.nil? || line.strip.empty?
            end

            # Returns [status_line, html]. Only /callback?... completes the flow;
            # anything else (favicon, probes) gets a 404 and keeps listening.
            def handle_request(request_line)
              target = request_line.to_s.split[1].to_s
              return ['404 Not Found', 'Not Found'] unless target.start_with?('/callback?')

              params = capture_callback(target)
              if params['code']
                ['200 OK', CallbackPage.success_html]
              else
                ['400 Bad Request', CallbackPage.failure_html(params['error'] || 'missing_code', params['error_description'])]
              end
            end

            def capture_callback(target)
              query = target.split('?', 2).last
              params = URI.decode_www_form(query).to_h

              @mutex.synchronize do
                @result = {
                  code:              params['code'],
                  state:             params['state'],
                  error:             params['error'],
                  error_description: params['error_description']
                }.compact
                @cv.broadcast
              end
              params
            end

            def log_debug(message)
              log.debug("[Entra::CallbackServer] #{message}")
            end
          end
        end
      end
    end
  end
end
