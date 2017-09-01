module Bitcoin

  class Validation

    # check transaction validation
    def check_tx(tx, state)
      # Basic checks that don't depend on any context
      if tx.inputs.empty?
        return state.DoS(10, reject_code: Message::Reject::CODE_INVALID, reject_resoin: 'bad-txns-vin-empty')
      end

      if tx.outputs.empty?
        return state.DoS(100, reject_code: Message::Reject::CODE_INVALID, reject_resoin: 'bad-txns-vout-empty')
      end

      # Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
      if tx.serialize_old_format.bytesize * Bitcoin::WITNESS_SCALE_FACTOR > Bitcoin::MAX_BLOCK_WEIGHT
        return state.DoS(100, reject_code: Message::Reject::CODE_INVALID, reject_resoin: 'bad-txns-oversize')
      end

      true
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

    def DoS(level, ret: false, reject_code: 0, reject_resoin: '', corruption_in: false, debug_message: '')
      @reject_code = reject_code
      @reject_reason = reject_resoin
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