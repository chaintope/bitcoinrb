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
        tx.inputs.each do |i|
          if i.out_point.nil? || !i.out_point.valid?
            return state.DoS(10, reject_code: Message::Reject::CODE_INVALID, reject_reason: 'bad-txns-prevout-null')
          end
        end
      end
      true
    end

    # check proof of work
    def check_block_header(header, state)
      header.hash
      header.bits

    end

    def check_block(block, state)
      # check block header
      return false unless check_block_header(block.header, state)

      # check merkle root

      # size limits

      # first tx is coinbase?

      # check tx count

      # check sigop count
    end

  end

  class ValidationState

    MODE = {valid: 0, invlid: 1, error: 2}

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