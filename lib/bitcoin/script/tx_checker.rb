module Bitcoin
  class TxChecker

    attr_reader :tx
    attr_reader :input_index
    attr_reader :amount
    attr_reader :prevouts
    attr_accessor :error_code

    def initialize(tx: nil, amount: 0, input_index: nil, prevouts: [])
      @tx = tx
      @input_index = input_index
      @prevouts = prevouts
      @amount = input_index && prevouts[input_index] ? prevouts[input_index].value : amount
    end

    # check ecdsa signature
    # @param [String] sig signature with hex format
    # @param [String] pubkey with hex format.
    # @param [Bitcoin::Script] script_code
    # @param [Integer] sig_version
    # @return [Boolean] verification result
    def check_sig(sig, pubkey, script_code, sig_version, allow_hybrid: false)
      return false if sig.empty?
      sig = sig.htb
      hash_type = sig[-1].unpack1('C')
      sig = sig[0..-2]
      sighash = tx.sighash_for_input(input_index, script_code, opts: {amount: amount}, hash_type: hash_type, sig_version: sig_version)
      key_type = pubkey.start_with?('02') || pubkey.start_with?('03') ? Key::TYPES[:compressed] : Key::TYPES[:uncompressed]
      begin
        key = Key.new(pubkey: pubkey, key_type: key_type, allow_hybrid: allow_hybrid)
        key.verify(sig, sighash)
      rescue Exception
        false
      end
    end

    # check schnorr signature.
    # @param [String] sig schnorr signature with hex format.
    # @param [String] pubkey a public key with hex fromat.
    # @param [Symbol] sig_version whether :taproot or :tapscript
    # @return [Boolean] verification result
    def check_schnorr_sig(sig, pubkey, sig_version, opts = {})
      return false unless [:taproot, :tapscript].include?(sig_version)
      return false if prevouts.size < input_index

      sig = sig.htb
      return set_error(SCRIPT_ERR_SCHNORR_SIG_SIZE) unless [64, 65].include?(sig.bytesize)

      hash_type = SIGHASH_TYPE[:default]
      if sig.bytesize == 65
        hash_type = sig[-1].unpack1('C')
        sig = sig[0..-2]
        return set_error(SCRIPT_ERR_SCHNORR_SIG_HASHTYPE) if hash_type == SIGHASH_TYPE[:default] # hash type can not specify 0x00.
      end

      return set_error(SCRIPT_ERR_SCHNORR_SIG_HASHTYPE) unless (hash_type <= 0x03 || (hash_type >= 0x81 && hash_type <= 0x83))

      opts[:prevouts] = prevouts

      begin
        sighash = tx.sighash_for_input(input_index, opts: opts, hash_type: hash_type, sig_version: sig_version)
        key = Key.new(pubkey: "02#{pubkey}", key_type: Key::TYPES[:compressed])
        key.verify(sig, sighash, algo: :schnorr)
      rescue ArgumentError
        return set_error(SCRIPT_ERR_SCHNORR_SIG_HASHTYPE)
      end
    end

    def check_locktime(locktime)
      # There are two kinds of nLockTime: lock-by-blockheight and lock-by-blocktime,
      # distinguished by whether nLockTime < LOCKTIME_THRESHOLD.

      # We want to compare apples to apples, so fail the script unless the type of nLockTime being tested is the same as the nLockTime in the transaction.
      unless ((tx.lock_time < LOCKTIME_THRESHOLD && locktime < LOCKTIME_THRESHOLD) ||
          (tx.lock_time >= LOCKTIME_THRESHOLD && locktime >= LOCKTIME_THRESHOLD))
        return false
      end

      # Now that we know we're comparing apples-to-apples, the comparison is a simple numeric one.
      return false if locktime > tx.lock_time

      # Finally the nLockTime feature can be disabled and thus CHECKLOCKTIMEVERIFY bypassed if every txin has been finalized by setting nSequence to maxint.
      # The transaction would be allowed into the blockchain, making the opcode ineffective.
      # Testing if this vin is not final is sufficient to prevent this condition.
      # Alternatively we could test all inputs, but testing just this input minimizes the data required to prove correct CHECKLOCKTIMEVERIFY execution.
      return false if TxIn::SEQUENCE_FINAL == tx.inputs[input_index].sequence

      true
    end

    def check_sequence(sequence)
      tx_sequence = tx.inputs[input_index].sequence
      # Fail if the transaction's version number is not set high enough to trigger BIP 68 rules.
      return false if tx.version < 2

      # Sequence numbers with their most significant bit set are not consensus constrained.
      # Testing that the transaction's sequence number do not have this bit set prevents using this property to get around a CHECKSEQUENCEVERIFY check.
      return false unless tx_sequence & TxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG == 0

      # Mask off any bits that do not have consensus-enforced meaning before doing the integer comparisons
      locktime_mask = TxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | TxIn::SEQUENCE_LOCKTIME_MASK
      tx_sequence_masked = tx_sequence & locktime_mask
      sequence_masked = sequence & locktime_mask

      # There are two kinds of nSequence: lock-by-blockheight and lock-by-blocktime,
      # distinguished by whether sequence_masked < TxIn#SEQUENCE_LOCKTIME_TYPE_FLAG.
      # We want to compare apples to apples, so fail the script
      # unless the type of nSequenceMasked being tested is the same as the nSequenceMasked in the transaction.
      unless ((tx_sequence_masked < TxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && sequence_masked < TxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) ||
          (tx_sequence_masked >= TxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && sequence_masked >= TxIn::SEQUENCE_LOCKTIME_TYPE_FLAG))
        return false
      end

      # Now that we know we're comparing apples-to-apples, the comparison is a simple numeric one.
      sequence_masked <= tx_sequence_masked
    end

    def has_error?
      !@error_code.nil?
    end

    private

    def set_error(code)
      @error_code = code
      false
    end

  end
end