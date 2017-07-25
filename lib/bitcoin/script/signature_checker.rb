module Bitcoin
  class SignatureChecker

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
      sighash = nil
      if sig_version == ScriptInterpreter::SIGVERSION_WITNESS_V0
        # TODO
      else
        sighash = tx.sighash_for_input(input_index: input_index, hash_type: hash_type, script_pubkey: script_code)
      end
      key = Bitcoin::Key.new(pubkey: pubkey)
      key.verify(sig, sighash)
    end

  end
end