module Bitcoin
  class TxChecker

    attr_reader :tx
    attr_reader :input_index
    attr_reader :amount

    def initialize(tx: nil, amount: 0, input_index: nil)
      @tx = tx
      @amount = amount
      @input_index = input_index
    end

    # check signature
    # @param [String] script_sig
    # @param [String] pubkey
    # @param [Bitcoin::Script] script_code
    # @param [Integer] sig_version
    def check_sig(script_sig, pubkey, script_code, sig_version)
      return false if script_sig.empty?
      script_sig = script_sig.htb
      hash_type = script_sig[-1].unpack('C').first
      sig = script_sig[0..-2]
      if sig_version == ScriptInterpreter::SIG_VERSION[:witness_v0]
        sighash = tx.sighash_for_input(input_index: input_index, hash_type: hash_type,
                                       script_code: script_code, amount: amount, sig_version: sig_version)
      else
        sighash = tx.sighash_for_input(input_index: input_index, hash_type: hash_type,
                                       script_code: script_code, sig_version: sig_version)
      end
      key = Bitcoin::Key.new(pubkey: pubkey)
      key.verify(sig, sighash)
    end

    def check_locktime
      # TODO
    end

    def check_sequence
      # TODO
    end

  end
end