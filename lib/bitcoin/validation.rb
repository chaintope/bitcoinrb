module Bitcoin

  class Validation

    # check transaction validation
    def check_tx(tx, state)
      # Basic checks that don't depend on any context
      if tx.inputs.empty?
        return state.DoS(10, reject_code: Message::Reject::CODE_INVALID, reject_reason: 'bad-txns-vin-empty')
      end

      if tx.outputs.empty?
        return state.DoS(100, reject_code: Message::Reject::CODE_INVALID, reject_reason: 'bad-txns-vout-empty')
      end

      # Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
      if tx.serialize_old_format.bytesize * Bitcoin::WITNESS_SCALE_FACTOR > Bitcoin::MAX_BLOCK_WEIGHT
        return state.DoS(100, reject_code: Message::Reject::CODE_INVALID, reject_reason: 'bad-txns-oversize')
      end

      # Check for negative or overflow output values
      amount = 0
      tx.outputs.each do |o|
        return state.DoS(100, reject_code: Message::Reject::CODE_INVALID, reject_reason: 'bad-txns-vout-negative') if o.value < 0
        return state.DoS(100, reject_code: Message::Reject::CODE_INVALID, reject_reason: 'bad-txns-vout-toolarge') if MAX_MONEY < o.value
        amount += o.value
        return state.DoS(100, reject_code: Message::Reject::CODE_INVALID, reject_reason: 'bad-txns-vout-toolarge') if MAX_MONEY < amount
      end

      # Check for duplicate inputs - note that this check is slow so we skip it in CheckBlock
      out_points = tx.inputs.map{|i|i.out_point.to_payload}
      unless out_points.size == out_points.uniq.size
        return state.DoS(100, reject_code: Message::Reject::CODE_INVALID, reject_reason: 'bad-txns-inputs-duplicate')
      end

      if tx.coinbase_tx?
        if tx.inputs[0].script_sig.size < 2 || tx.inputs[0].script_sig.size > 100
          return state.DoS(100, reject_code: Message::Reject::CODE_INVALID, reject_reason: 'bad-cb-length')
        end
      else
        # Only the null prevout (zero hash and index 0xffffffff) is rejected, as COutPoint::IsNull in
        # Bitcoin Core. An index of -1 is the default of OutPoint and serializes as 0xffffffff.
        null_payload = OutPoint.create_coinbase_outpoint.to_payload
        tx.inputs.each do |i|
          if i.out_point.nil? || i.out_point.to_payload == null_payload
            return state.DoS(10, reject_code: Message::Reject::CODE_INVALID, reject_reason: 'bad-txns-prevout-null')
          end
        end
      end
      true
    end

    # Check the proof of work of a block header, as CheckBlockHeader in Bitcoin Core.
    # @param [Bitcoin::BlockHeader] header
    # @param [Bitcoin::ValidationState] state
    # @return [Boolean]
    def check_block_header(header, state)
      unless header.valid_pow?
        return state.DoS(50, reject_code: Message::Reject::CODE_INVALID, reject_reason: 'high-hash', debug_message: 'proof of work failed')
      end
      true
    end

    # Check a block without any context, as CheckBlock in Bitcoin Core: the header, the merkle root,
    # the size limits, the coinbase, every tx and the legacy sigop count.
    # @param [Bitcoin::Block] block
    # @param [Bitcoin::ValidationState] state
    # @return [Boolean]
    def check_block(block, state)
      return false unless check_block_header(block.header, state)

      txs = block.transactions
      # A block without any tx has no merkle root to check, and fails the size limits below.
      unless txs.empty?
        if block.calculate_merkle_root != block.header.merkle_root
          return state.DoS(100, reject_code: Message::Reject::CODE_INVALID, reject_reason: 'bad-txnmrklroot', corruption_in: true, debug_message: 'hashMerkleRoot mismatch')
        end
        # CVE-2012-2459
        if block.merkle_root_mutated?
          return state.DoS(100, reject_code: Message::Reject::CODE_INVALID, reject_reason: 'bad-txns-duplicate', corruption_in: true, debug_message: 'duplicate transaction')
        end
      end

      # Size limits, without the witness, which has not been checked for malleability.
      if txs.empty? || txs.size * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || block.stripped_size * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT
        return state.DoS(100, reject_code: Message::Reject::CODE_INVALID, reject_reason: 'bad-blk-length', debug_message: 'size limits failed')
      end

      unless txs.first.coinbase_tx?
        return state.DoS(100, reject_code: Message::Reject::CODE_INVALID, reject_reason: 'bad-cb-missing', debug_message: 'first tx is not coinbase')
      end
      if txs[1..].any?(&:coinbase_tx?)
        return state.DoS(100, reject_code: Message::Reject::CODE_INVALID, reject_reason: 'bad-cb-multiple', debug_message: 'more than one coinbase')
      end

      txs.each { |tx| return false unless check_tx(tx, state) }

      sigops = txs.sum { |tx| legacy_sigop_count(tx) }
      if sigops * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST
        return state.DoS(100, reject_code: Message::Reject::CODE_INVALID, reject_reason: 'bad-blk-sigops', debug_message: 'out-of-bounds SigOpCount')
      end
      true
    end

    private

    # Count the sigops of the scriptSigs and scriptPubkeys of +tx+, as GetLegacySigOpCount in Bitcoin Core:
    # a CHECKMULTISIG counts as 20 whatever its key count.
    def legacy_sigop_count(tx)
      tx.inputs.sum { |i| script_sigop_count(i.script_sig) } + tx.outputs.sum { |o| script_sigop_count(o.script_pubkey) }
    end

    def script_sigop_count(script)
      script.chunks.sum do |chunk|
        next 0 if chunk.empty?
        case chunk.opcode
        when Opcodes::OP_CHECKSIG, Opcodes::OP_CHECKSIGVERIFY then 1
        when Opcodes::OP_CHECKMULTISIG, Opcodes::OP_CHECKMULTISIGVERIFY then MAX_PUBKEYS_PER_MULTISIG
        else 0
        end
      end
    end

  end

  class ValidationState

    MODE = {valid: 0, invalid: 1, error: 2}

    attr_accessor :mode
    attr_accessor :n_dos
    attr_accessor :reject_reason
    attr_accessor :reject_code
    attr_accessor :corruption_possible
    attr_accessor :debug_message

    def initialize
      @mode = MODE[:valid]
      @n_dos = 0
      @reject_code = 0
      @corruption_possible = false
    end

    def DoS(level, ret: false, reject_code: 0, reject_reason: '', corruption_in: false, debug_message: '')
      @reject_code = reject_code
      @reject_reason = reject_reason
      @corruption_possible = corruption_in
      @debug_message = debug_message
      return ret if mode == MODE[:error]
      @n_dos += level
      @mode = MODE[:invalid]
      ret
    end

    def valid?
      mode == MODE[:valid]
    end

    def invalid?
      mode == MODE[:invalid]
    end

    def error?
      mode == MODE[:error]
    end
  end
end