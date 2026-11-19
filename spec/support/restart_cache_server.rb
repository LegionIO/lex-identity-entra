# frozen_string_literal: true

require 'fileutils'
require 'socket'
require 'tmpdir'

class RestartCacheServer
  include Legion::Logging::Helper

  attr_reader :url

  def start
    @url = ENV.fetch('ENTRA_TEST_REDIS_URL', nil)
    @url ||= 'redis://127.0.0.1:6379' if ENV['CI'] == 'true'
    return if @url

    port = TCPServer.open('127.0.0.1', 0) { |socket| socket.addr[1] }
    @url = "redis://127.0.0.1:#{port}"
    @directory = Dir.mktmpdir('entra-redis-')
    output = File.join(@directory, 'redis.log')
    @pid = ::Process.spawn('redis-server', '--bind', '127.0.0.1', '--port', port.to_s,
                           '--save', '', '--appendonly', 'no', '--dir', @directory,
                           out: output, err: %i[child out])
    100.times do
      return if File.exist?(output) && File.read(output).include?('Ready to accept connections')

      sleep 0.05
    end
    raise 'Isolated Redis did not start; install redis-server or set ENTRA_TEST_REDIS_URL'
  end

  def stop
    return unless @pid

    ::Process.kill('TERM', @pid)
    ::Process.wait(@pid)
  rescue Errno::ESRCH, Errno::ECHILD => e
    handle_exception(e, level: :warn, operation: :stop_restart_cache_fixture)
  ensure
    FileUtils.remove_entry(@directory) if @directory && File.directory?(@directory)
  end
end
