module Bitcoin

  class ScriptInterpreter
    include Bitcoin::Opcodes

    attr_reader :stack
    attr_reader :debug
    attr_accessor :error

    # initialize runner
    def initialize
      @stack = []
      @debug = []
    end

    # eval script
    # @param [Bitcoin::Script] script_sig a signature script (unlock script which data push only)
    # @param [Bitcoin::Script] script_pubkey a script pubkey (locking script)
    # @param [Bitcoin::ScriptWitness] witness a witness script
    # @return [Boolean] result
    def verify(script_sig, script_pubkey, witness = nil)
      return set_error(ScriptError::SCRIPT_ERR_SIG_PUSHONLY) unless script_sig.push_only?

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
            if c.bytesize == 1 && Opcodes.small_int_to_opcode(c.ord)
              @stack << c.ord
            else
              @stack << c
            end
          else
            opcode = c.ord
            if Opcodes.opcode_to_small_int(opcode)
              hoge = Opcodes.opcode_to_small_int(opcode)
              @stack << Opcodes.opcode_to_small_int(opcode)
            else
              case opcode
                when OP_DEPTH
                  @stack << @stack.size
                when OP_EQUAL, OP_EQUALVERIFY
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if @stack.size < 2
                  e1, e2 = @stack.pop(2)
                  result = e1 == e2
                  @stack << result
                  if opcode == OP_EQUALVERIFY
                    if result
                      @stack.pop
                    else
                      return set_error(ScriptError::SCRIPT_ERR_EQUALVERIFY)
                    end
                  end
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

  end

end