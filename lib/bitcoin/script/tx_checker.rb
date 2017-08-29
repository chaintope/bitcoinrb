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
      sighash = tx.sighash_for_input(input_index: input_index, hash_type: hash_type,
                                     script_code: script_code, amount: amount, sig_version: sig_version)
      key = Bitcoin::Key.new(pubkey: pubkey)
      key.verify(sig, sighash)
    end

    def check_locktime(locktime)
      # TODO
    end

    def check_sequence(sequence)
      tx_sequence = tx.inputs[input_index].sequence
      # Fail if the transaction's version number is not set high enough to trigger BIP 68 rules.
      return false if tx.version < 2

      # Sequence numbers with their most significant bit set are not consensus constrained.
      # Testing that the transaction's sequence number do not have this bit set prevents using this property to get around a CHECKSEQUENCEVERIFY check.
      return false unless tx_sequence & Bitcoin::TxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG == 0

      # Mask off any bits that do not have consensus-enforced meaning before doing the integer comparisons
      locktime_mask = Bitcoin::TxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | Bitcoin::TxIn::SEQUENCE_LOCKTIME_MASK
      tx_sequence_masked = tx_sequence & locktime_mask
      sequence_masked = sequence & locktime_mask

      # There are two kinds of nSequence: lock-by-blockheight and lock-by-blocktime,
      # distinguished by whether sequence_masked < TxIn#SEQUENCE_LOCKTIME_TYPE_FLAG.
      # We want to compare apples to apples, so fail the script
      # unless the type of nSequenceMasked being tested is the same as the nSequenceMasked in the transaction.
      if ((tx_sequence_masked < Bitcoin::TxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && sequence_masked < Bitcoin::TxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) ||
          (tx_sequence_masked >= Bitcoin::TxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && sequence_masked >= Bitcoin::TxIn::SEQUENCE_LOCKTIME_TYPE_FLAG))
        return false
      end

      # Now that we know we're comparing apples-to-apples, the comparison is a simple numeric one.
      sequence_masked <= tx_sequence_masked
    end

  end
end