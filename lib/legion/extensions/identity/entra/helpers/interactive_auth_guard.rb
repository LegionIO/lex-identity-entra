# frozen_string_literal: true

require 'fileutils'
require 'open3'
require 'rbconfig'

module Legion
  module Extensions
    module Identity
      module Entra
        module Helpers
          # Guards interactive (browser / device-code) sign-in so background actors
          # can never stack up login tabs:
          #
          # * single-flight: one attempt at a time per process (Mutex) and across
          #   processes (flock on a lock file)
          # * exponential backoff after an unanswered automatic attempt, and a
          #   hard stop after +max_auto_attempts+ until the user signs in manually
          #   (any successful TokenManager.save_token(:delegated) resets the guard)
          # * optional skip while the macOS screen is locked or the user is idle
          # * one clear warning telling the user how to re-authenticate
          #
          # Backoff state is persisted (no secrets) so a daemon restart does not
          # immediately reopen a tab.
          module InteractiveAuthGuard
            extend self
            include Legion::Logging::Helper
            include Legion::JSON::Helper

            REAUTH_HINT = 'Run `legionio auth teams` to sign in to Microsoft Teams / Entra again.'
            DEFAULTS = {
              backoff_base_seconds:    1800,
              backoff_max_seconds:     21_600,
              max_auto_attempts:       3,
              skip_when_screen_locked: true,
              skip_when_idle_seconds:  900
            }.freeze
            RUN_DIR = File.join(Dir.home, '.legionio', 'run')
            SUCCESS_KEYS = %i[access_token].freeze

            MUTEX = Mutex.new
            STATE_MUTEX = Mutex.new

            # Runs the block as an interactive sign-in attempt.
            #
            # automatic: true  -> background actor; subject to backoff, suspension, screen lock/idle
            # automatic: false -> user asked for it (CLI); only single-flight applies
            #
            # Returns the block's result, or { error:, description: } when skipped.
            def run(automatic: false, &)
              if automatic
                skip = automatic_skip_reason
                return skipped(skip) if skip
              end

              return busy('in_process') unless MUTEX.try_lock

              begin
                with_process_lock { record_outcome(yield, automatic: automatic) }
              ensure
                MUTEX.unlock
              end
            end

            def in_flight?
              MUTEX.locked?
            end

            # Clears backoff/suspension. Called after any successful delegated sign-in.
            def reset!(reason: 'success')
              STATE_MUTEX.synchronize do
                state = current_state
                had_state = state[:failures].to_i.positive? || state[:suspended] || state[:notified]
                next unless had_state

                @state = blank_state
                persist_state
                log.info("[entra][auth_guard] action=reset reason=#{reason}")
              end
            end

            def state
              STATE_MUTEX.synchronize { current_state.dup }
            end

            # Logs a single warning (once per process until the next successful
            # sign-in) telling the user how to re-authenticate.
            def notify_reauth_required(reason)
              STATE_MUTEX.synchronize do
                state = current_state
                if state[:notified]
                  log.debug("[entra][auth_guard] action=notify_suppressed reason=#{reason}")
                  return false
                end

                state[:notified] = reason.to_s
                persist_state
              end
              log.warn("Microsoft Teams / Entra sign-in required (#{reason}). #{REAUTH_HINT}")
              true
            end

            def screen_locked?
              return false unless darwin?

              out, status = Open3.capture2('/usr/sbin/ioreg', '-n', 'Root', '-d1')
              status.success? && out.include?('"CGSSessionScreenIsLocked"=Yes')
            rescue StandardError => e
              handle_exception(e, level: :debug, operation: 'entra.auth_guard.screen_locked?')
              false
            end

            # Seconds since the last keyboard/mouse input (macOS only), or nil.
            def idle_seconds
              return nil unless darwin?

              out, status = Open3.capture2('/usr/sbin/ioreg', '-c', 'IOHIDSystem', '-d', '4')
              return nil unless status.success?

              match = out.match(/"HIDIdleTime"\s*=\s*(\d+)/)
              match ? match[1].to_i / 1_000_000_000 : nil
            rescue StandardError => e
              handle_exception(e, level: :debug, operation: 'entra.auth_guard.idle_seconds')
              nil
            end

            def lock_path
              setting(:lock_path) || File.join(RUN_DIR, 'entra_browser_auth.lock')
            end

            def state_path
              setting(:state_path) || File.join(RUN_DIR, 'entra_browser_auth_state.json')
            end

            # Test helper: forget in-memory state so it is re-read from disk.
            def reload!
              STATE_MUTEX.synchronize do
                @state = nil
                @state_mtime = nil
              end
            end

            private

            def automatic_skip_reason
              state = self.state
              if state[:suspended]
                log.debug("[entra][auth_guard] action=skip reason=suspended failures=#{state[:failures]}")
                return 'suspended'
              end

              retry_at = state[:next_attempt_at]
              if retry_at && Time.now.to_i < retry_at
                log.debug("[entra][auth_guard] action=skip reason=backoff retry_in=#{retry_at - Time.now.to_i}s")
                return 'backoff'
              end

              if config[:skip_when_screen_locked] && screen_locked?
                log.debug('[entra][auth_guard] action=skip reason=screen_locked')
                return 'screen_locked'
              end

              idle_limit = config[:skip_when_idle_seconds].to_i
              if idle_limit.positive?
                idle = idle_seconds
                if idle && idle >= idle_limit
                  log.debug("[entra][auth_guard] action=skip reason=user_idle idle=#{idle}s limit=#{idle_limit}s")
                  return 'user_idle'
                end
              end

              nil
            end

            def with_process_lock
              path = lock_path
              FileUtils.mkdir_p(File.dirname(path))
              File.open(path, File::RDWR | File::CREAT, 0o600) do |file|
                unless file.flock(File::LOCK_EX | File::LOCK_NB)
                  holder = file.read.to_s.strip
                  return busy('other_process', holder: holder)
                end

                begin
                  file.truncate(0)
                  file.write(::Process.pid.to_s)
                  file.flush
                  log.debug("[entra][auth_guard] action=lock_acquired path=#{path} pid=#{::Process.pid}")
                  yield
                ensure
                  file.truncate(0)
                  file.flock(File::LOCK_UN)
                end
              end
            end

            def record_outcome(result, automatic:)
              if success?(result)
                reset!
              elsif automatic
                record_failure(result)
              end
              result
            end

            def success?(result)
              return false unless result.is_a?(Hash)

              body = result[:result]
              body.is_a?(Hash) && SUCCESS_KEYS.all? { |k| body[k] || body[k.to_s] }
            end

            def record_failure(result)
              error = result.is_a?(Hash) ? (result[:error] || 'no_token') : 'no_token'
              cfg = config
              warning = nil
              STATE_MUTEX.synchronize do
                state = current_state
                state[:failures] = state[:failures].to_i + 1
                state[:last_error] = error.to_s
                state[:last_attempt_at] = Time.now.to_i
                if state[:failures] >= cfg[:max_auto_attempts].to_i
                  state[:suspended] = true
                  state[:next_attempt_at] = nil
                  warning = "Automatic Microsoft Teams / Entra browser sign-in paused after #{state[:failures]} " \
                            "unanswered attempts (last error: #{error}). No more login tabs will be opened. #{REAUTH_HINT}"
                else
                  delay = backoff_delay(state[:failures], cfg)
                  state[:next_attempt_at] = Time.now.to_i + delay
                  warning = "Microsoft Teams / Entra browser sign-in was not completed (#{error}). " \
                            "Will retry automatically in #{format_duration(delay)} " \
                            "(attempt #{state[:failures]}/#{cfg[:max_auto_attempts]}). #{REAUTH_HINT}"
                end
                state[:notified] = 'auto_auth_failed'
                persist_state
              end
              log.warn(warning)
            end

            def backoff_delay(failures, cfg)
              base = cfg[:backoff_base_seconds].to_i
              max = cfg[:backoff_max_seconds].to_i
              [base * (2**(failures - 1)), max].min
            end

            def format_duration(seconds)
              return "#{seconds}s" if seconds < 120
              return "#{seconds / 60} minutes" if seconds < 7200

              "#{(seconds / 3600.0).round(1)} hours"
            end

            def skipped(reason)
              notify_reauth_required('automatic sign-in deferred') if %w[screen_locked user_idle].include?(reason)
              { error: 'auth_skipped', reason: reason,
                description: "interactive sign-in skipped (#{reason}). #{REAUTH_HINT}" }
            end

            def busy(scope, holder: nil)
              log.info("[entra][auth_guard] action=skip reason=in_progress scope=#{scope} holder=#{holder}")
              { error: 'auth_in_progress', reason: scope,
                description: "another Microsoft sign-in is already in progress#{" (pid #{holder})" unless holder.to_s.empty?}" }
            end

            # Re-reads the state file when another process (e.g. `legionio entra login`)
            # changed it, so a sign-in elsewhere clears this daemon's backoff.
            def current_state
              mtime = state_file_mtime
              if @state.nil? || (mtime && mtime != @state_mtime)
                notified = @state&.dig(:notified)
                @state = load_state
                @state[:notified] ||= notified if @state[:failures].to_i.positive? || @state[:suspended]
                @state_mtime = mtime
              end
              @state
            end

            def state_file_mtime
              path = state_path
              File.exist?(path) ? File.mtime(path) : nil
            end

            def blank_state
              { failures: 0, suspended: false, next_attempt_at: nil, last_error: nil,
                last_attempt_at: nil, notified: nil }
            end

            def load_state
              path = state_path
              return blank_state unless File.exist?(path)

              raw = json_load(File.read(path))
              return blank_state unless raw.is_a?(Hash)

              # :notified is per-process so each daemon start logs the hint once.
              blank_state.merge(raw.transform_keys(&:to_sym).slice(*blank_state.keys).except(:notified))
            rescue StandardError => e
              handle_exception(e, level: :warn, operation: 'entra.auth_guard.load_state', path: path)
              blank_state
            end

            def persist_state
              path = state_path
              FileUtils.mkdir_p(File.dirname(path))
              File.write(path, json_dump(@state.except(:notified)))
              File.chmod(0o600, path)
              @state_mtime = state_file_mtime
            rescue StandardError => e
              handle_exception(e, level: :warn, operation: 'entra.auth_guard.persist_state', path: path)
            end

            def config
              DEFAULTS.to_h { |key, default| [key, setting(key).nil? ? default : setting(key)] }
            end

            def setting(key)
              Legion::Settings.dig(:identity, :entra, :delegated, :browser_auth, key)
            rescue StandardError => e
              handle_exception(e, level: :debug, operation: 'entra.auth_guard.setting', key: key)
              nil
            end

            def darwin?
              RbConfig::CONFIG['host_os'].include?('darwin')
            end
          end
        end
      end
    end
  end
end
