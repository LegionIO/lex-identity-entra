# frozen_string_literal: true

require 'socket'
require 'uri'

module Legion
  module Extensions
    module Identity
      module Entra
        module Helpers
          class CallbackServer
            include Legion::Extensions::Helpers::Lex if Legion::Extensions.const_defined?(:Helpers, false) &&
                                                        Legion::Extensions::Helpers.const_defined?(:Lex, false)

            RESPONSE_HTML = <<~HTML
              <html><body style="font-family:sans-serif;text-align:center;padding:40px;">
              <h2>Authentication complete</h2><p>You can close this window.</p></body></html>
            HTML

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
              loop do
                client = @server.accept
                request_line = client.gets
                drain_headers(client)
                capture_callback(request_line) if request_line&.include?('/callback?')

                client.print "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n#{RESPONSE_HTML}"
                client.close
                break if @result
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
              loop do
                line = client.gets
                break if line.nil? || line.strip.empty?
              end
            end

            def capture_callback(request_line)
              query = request_line.split[1].split('?', 2).last
              params = URI.decode_www_form(query).to_h

              @mutex.synchronize do
                @result = {
                  code:  params['code'],
                  state: params['state']
                }
                @cv.broadcast
              end
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
