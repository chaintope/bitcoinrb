module Bitcoin

  SCRIPT_VERIFY_NONE      = 0
  SCRIPT_VERIFY_P2SH      = (1 << 0)
  SCRIPT_VERIFY_STRICTENC = (1 << 1)
  SCRIPT_VERIFY_DERSIG    = (1 << 2)
  SCRIPT_VERIFY_LOW_S     = (1 << 3)
  SCRIPT_VERIFY_NULLDUMMY = (1 << 4)
  SCRIPT_VERIFY_SIGPUSHONLY = (1 << 5)
  SCRIPT_VERIFY_MINIMALDATA = (1 << 6)
  SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1 << 7)
  SCRIPT_VERIFY_CLEANSTACK = (1 << 8)

  class ScriptInterpreter
    include Bitcoin::Opcodes

    attr_reader :stack
    attr_reader :debug
    attr_reader :flags
    attr_accessor :error

    # initialize runner
    def initialize(flags: [])
      @stack = []
      @debug = []
      @flags = flags
    end

    # eval script
    # @param [Bitcoin::Script] script_sig a signature script (unlock script which data push only)
    # @param [Bitcoin::Script] script_pubkey a script pubkey (locking script)
    # @param [Bitcoin::ScriptWitness] witness a witness script
    # @return [Boolean] result
    def verify(script_sig, script_pubkey, witness = nil)

      return set_error(ScriptError::SCRIPT_ERR_SIG_PUSHONLY) if flag?(SCRIPT_VERIFY_SIGPUSHONLY) && !script_sig.data_only?

      return false unless eval_script(script_sig)
      return false unless eval_script(script_pubkey)
      return set_error(ScriptError::SCRIPT_ERR_EVAL_FALSE) if stack.empty? || stack.last == false

      if script_pubkey.witness_program?
        return set_error(ScriptError::SCRIPT_ERR_WITNESS_MALLEATED) unless script_sig.size == 0
        return false unless verify_witness_program(witness, 0, script_pubkey)
      end

      if script_pubkey.p2sh?
        # TODO
      end
      true
    end

    def set_error(err_code)
      @error = ScriptError.new(err_code)
      false
    end

    def verify_sig

    end

    def verify_witness_program(witness, version, witness_program)

    end

    def eval_script(script)
      begin
        script.chunks.each do |c|
          if c.pushdata?
            # if c.bytesize == 1 && Opcodes.small_int_to_opcode(c.ord)
            #   @stack << c.ord
            # else
              @stack << c.pushed_data.bth
            # end
          else
            opcode = c.ord
            small_int = Opcodes.opcode_to_small_int(opcode)
            if small_int
              @stack << small_int
            else
              case opcode
                when OP_DEPTH
                  @stack << @stack.size
                when OP_EQUAL, OP_EQUALVERIFY
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if @stack.size < 2
                  a, b = pop_string(2)
                  result = a == b
                  @stack << result
                  if opcode == OP_EQUALVERIFY
                    if result
                      @stack.pop
                    else
                      return set_error(ScriptError::SCRIPT_ERR_EQUALVERIFY)
                    end
                  end
                when OP_ADD
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if @stack.size < 2
                  a, b = pop_int(2)
                  @stack << (a + b)
                else
                  return set_error(ScriptError::SCRIPT_ERR_BAD_OPCODE)
              end
            end
          end
        end
      rescue Exception => e
        puts e
        return set_error(ScriptError::SCRIPT_ERR_UNKNOWN_ERROR)
      end

      set_error(ScriptError::SCRIPT_ERR_OK)
      true
    end

    private

    def flag?(flag)
      (all_flags & flag) != 0
    end

    def all_flags
      result = SCRIPT_VERIFY_NONE
      flags.each{ |f| result |= f }
      result
    end

    def pop_int(count)
      stack.pop(count).map do |s|
        case s
          when String
            s.htb.reverse.bth.to_i(16)
          else
            s
        end
      end
    end

    def pop_string(count)
      stack.pop(count).map do |s|
        case s
          when Numeric
            if s < 256
              [s].pack('C')
            else
              hex = s.to_s(16)
              hex = '0' + hex unless hex.length % 2 == 0
              hex.htb.reverse.bth
            end
          else
            s
        end
      end
    end

  end



end