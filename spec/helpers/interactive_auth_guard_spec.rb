# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Legion::Extensions::Identity::Entra::Helpers::InteractiveAuthGuard do
  subject(:guard) { described_class }

  let(:success) { { result: { access_token: 'tok', refresh_token: 'r' } } }
  let(:timeout) { { error: 'timeout', description: 'No callback received within timeout' } }
  let(:log_io) { StringIO.new }

  before do
    allow(guard).to receive(:log).and_return(Logger.new(log_io))
  end

  def stub_settings(values)
    allow(Legion::Settings).to receive(:dig).and_call_original
    values.each do |key, value|
      allow(Legion::Settings).to receive(:dig)
        .with(:identity, :entra, :delegated, :browser_auth, key).and_return(value)
    end
  end

  describe '.run single-flight' do
    it 'rejects a concurrent attempt in the same process without running the block' do
      started = Queue.new
      release = Queue.new
      first = Thread.new do
        guard.run do
          started << true
          release.pop
          success
        end
      end
      started.pop

      calls = 0
      result = guard.run { calls += 1 }
      release << true
      first.join

      expect(calls).to eq(0)
      expect(result).to include(error: 'auth_in_progress', reason: 'in_process')
    end

    it 'rejects an attempt while another process holds the lock file' do
      File.open(guard.lock_path, File::RDWR | File::CREAT) do |f|
        f.write('4242')
        f.flush
        pid = fork do
          File.open(guard.lock_path, File::RDWR) do |lock|
            lock.flock(File::LOCK_EX)
            sleep 2
          end
        end
        sleep 0.3
        calls = 0
        result = guard.run { calls += 1 }
        expect(calls).to eq(0)
        expect(result).to include(error: 'auth_in_progress', reason: 'other_process')
      ensure
        Process.kill('TERM', pid) if pid
        Process.wait(pid) if pid
      end
    end

    it 'releases the lock after the attempt so the next one can run' do
      guard.run { timeout }
      expect(guard.run { success }).to eq(success)
      expect(guard.in_flight?).to be(false)
    end
  end

  describe '.run automatic backoff' do
    it 'backs off exponentially after unanswered automatic attempts' do
      guard.run(automatic: true) { timeout }
      first_retry = guard.state[:next_attempt_at]
      expect(first_retry - Time.now.to_i).to be_within(5).of(1800)

      calls = 0
      result = guard.run(automatic: true) { calls += 1 }
      expect(calls).to eq(0)
      expect(result).to include(error: 'auth_skipped', reason: 'backoff')

      allow(Time).to receive(:now).and_return(Time.at(first_retry + 1))
      guard.run(automatic: true) { timeout }
      expect(guard.state[:next_attempt_at] - first_retry).to be_within(5).of(3600)
    end

    it 'suspends automatic attempts after max_auto_attempts and logs how to re-authenticate' do
      stub_settings(max_auto_attempts: 2, backoff_base_seconds: 0)
      guard.run(automatic: true) { timeout }
      guard.run(automatic: true) { timeout }

      expect(guard.state[:suspended]).to be(true)
      expect(log_io.string).to include('paused after 2 unanswered attempts', 'legionio auth teams')

      calls = 0
      expect(guard.run(automatic: true) { calls += 1 }).to include(reason: 'suspended')
      expect(calls).to eq(0)
    end

    it 'still allows a manual (user-initiated) attempt while suspended, and success resets the guard' do
      stub_settings(max_auto_attempts: 1)
      guard.run(automatic: true) { timeout }
      expect(guard.state[:suspended]).to be(true)

      expect(guard.run(automatic: false) { success }).to eq(success)
      expect(guard.state).to include(suspended: false, failures: 0)
    end

    it 'does not count manual failures toward backoff' do
      guard.run(automatic: false) { timeout }
      expect(guard.state[:failures]).to eq(0)
    end

    it 'persists backoff across a restart (state reloaded from disk)' do
      guard.run(automatic: true) { timeout }
      guard.reload!
      expect(guard.run(automatic: true) { success }).to include(reason: 'backoff')
    end

    it 'skips automatic attempts while the screen is locked' do
      allow(guard).to receive(:screen_locked?).and_return(true)
      calls = 0
      expect(guard.run(automatic: true) { calls += 1 }).to include(reason: 'screen_locked')
      expect(calls).to eq(0)
      expect(guard.state[:failures]).to eq(0)
    end

    it 'skips automatic attempts while the user is idle' do
      allow(guard).to receive(:idle_seconds).and_return(3600)
      expect(guard.run(automatic: true) { success }).to include(reason: 'user_idle')
    end

    it 'ignores idle time when skip_when_idle_seconds is 0' do
      stub_settings(skip_when_idle_seconds: 0)
      allow(guard).to receive(:idle_seconds).and_return(3600)
      expect(guard.run(automatic: true) { success }).to eq(success)
    end
  end

  describe '.notify_reauth_required' do
    it 'logs the re-auth hint once until reset' do
      expect(guard.notify_reauth_required('token_expired')).to be(true)
      expect(guard.notify_reauth_required('token_expired')).to be(false)
      expect(guard.notify_reauth_required('refresh_token_rejected')).to be(false)
      expect(log_io.string.scan('legionio auth teams').size).to eq(1)

      guard.reset!
      expect(guard.notify_reauth_required('token_expired')).to be(true)
    end
  end

  describe '.screen_locked? / .idle_seconds' do
    before do
      allow(guard).to receive(:screen_locked?).and_call_original
      allow(guard).to receive(:idle_seconds).and_call_original
      allow(guard).to receive(:darwin?).and_return(true)
    end

    it 'detects a locked macOS session from ioreg' do
      allow(Open3).to receive(:capture2).and_return(['"CGSSessionScreenIsLocked"=Yes,', instance_double(Process::Status, success?: true)])
      expect(guard.screen_locked?).to be(true)
    end

    it 'reports unlocked when the key is absent' do
      allow(Open3).to receive(:capture2).and_return(['"kCGSSessionOnConsoleKey"=Yes', instance_double(Process::Status, success?: true)])
      expect(guard.screen_locked?).to be(false)
    end

    it 'parses HIDIdleTime nanoseconds into seconds' do
      allow(Open3).to receive(:capture2).and_return(['"HIDIdleTime" = 64029166000', instance_double(Process::Status, success?: true)])
      expect(guard.idle_seconds).to eq(64)
    end
  end
end
