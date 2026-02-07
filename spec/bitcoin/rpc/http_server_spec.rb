require 'spec_helper'

RSpec.describe Bitcoin::RPC::HttpServer do
  describe 'SUPPORTED_COMMANDS' do
    subject { described_class::SUPPORTED_COMMANDS }

    it 'is frozen' do
      expect(subject).to be_frozen
    end

    it 'includes all RequestHandler methods' do
      expected_commands = %w[
        getblockchaininfo
        stop
        getblockheader
        getpeerinfo
        sendrawtransaction
        decoderawtransaction
        decodescript
        createwallet
        listwallets
        getwalletinfo
        listaccounts
        encryptwallet
        getnewaddress
      ]
      expect(subject).to match_array(expected_commands)
    end

    it 'does not include undefined methods' do
      undefined_methods = %w[
        eval
        instance_eval
        class_eval
        module_eval
        exec
        system
        `
        spawn
        fork
        send
        __send__
        public_send
        method
        define_method
        remove_method
        undef_method
        instance_variable_set
        instance_variable_get
        const_set
        const_get
      ]
      undefined_methods.each do |method|
        expect(subject).not_to include(method), "SUPPORTED_COMMANDS should not include '#{method}'"
      end
    end
  end

  describe 'command validation' do
    # Test command validation logic without EventMachine
    def validate_command(command)
      unless Bitcoin::RPC::HttpServer::SUPPORTED_COMMANDS.include?(command)
        raise ArgumentError, "Unsupported method: #{command}"
      end
      command
    end

    describe 'with allowed commands' do
      %w[getblockchaininfo stop getblockheader decoderawtransaction].each do |cmd|
        it "allows '#{cmd}'" do
          expect { validate_command(cmd) }.not_to raise_error
        end
      end
    end

    describe 'with undefined commands' do
      # These are the attack vectors from the security advisory GHSA-q66h-m87m-j2q6
      %w[eval system exec instance_eval class_eval].each do |cmd|
        it "rejects '#{cmd}' to prevent remote code execution" do
          expect { validate_command(cmd) }.to raise_error(
            ArgumentError, "Unsupported method: #{cmd}"
          )
        end
      end
    end

    describe 'with arbitrary unknown commands' do
      %w[unknown_method foo bar __send__ public_send].each do |cmd|
        it "rejects '#{cmd}'" do
          expect { validate_command(cmd) }.to raise_error(
            ArgumentError, "Unsupported method: #{cmd}"
          )
        end
      end
    end
  end
end