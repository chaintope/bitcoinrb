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
  SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1 << 9) # Verify CHECKLOCKTIMEVERIFY (BIP-65)
  SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1 << 10) # support CHECKSEQUENCEVERIFY opcode (BIP-112)
  SCRIPT_VERIFY_WITNESS = (1 << 11) # Support segregated witness
  SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = (1 << 12) # Making v1-v16 witness program non-standard
  SCRIPT_VERIFY_MINIMALIF = (1 << 13) # Segwit script only: Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
  SCRIPT_VERIFY_NULLFAIL = (1 << 14) # Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
  SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = (1 << 15) # Public keys in segregated witness scripts must be compressed

  class ScriptInterpreter
    include Bitcoin::Opcodes

    attr_reader :stack
    attr_reader :alt_stack
    attr_reader :debug
    attr_reader :flags
    attr_accessor :error

    # initialize runner
    def initialize(flags: [])
      @stack, @alt_stack, @debug = [], [], []
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
        flow_stack = []
        last_code_separator_index = 0
        script.chunks.each_with_index do |c, index|
          need_exec = !flow_stack.include?(false)

          if c.pushdata?
            stack << c.pushed_data.bth
          else
            opcode = c.ord
            next unless (need_exec || (OP_IF <= opcode && opcode <= OP_ENDIF))
            small_int = Opcodes.opcode_to_small_int(opcode)
            if small_int && opcode != OP_0
              stack << small_int
            else
              case opcode
                when OP_0
                  stack << ''
                when OP_DEPTH
                  stack << stack.size
                when OP_EQUAL, OP_EQUALVERIFY
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  a, b = pop_string(2)
                  result = a == b
                  stack << (result ? 1 : 0)
                  if opcode == OP_EQUALVERIFY
                    if result
                      stack.pop
                    else
                      return set_error(ScriptError::SCRIPT_ERR_EQUALVERIFY)
                    end
                  end
                when OP_0NOTEQUAL
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << (pop_int == 0 ? 0 : 1)
                when OP_ADD
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  a, b = pop_int(2)
                  stack << (a + b)
                when OP_1ADD
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << (pop_int + 1)
                when OP_SUB
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  a, b = pop_int(2)
                  stack << (a - b)
                when OP_1SUB
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << (pop_int - 1)
                when OP_IF, OP_NOTIF
                  result = false
                  if need_exec
                    return set_error(ScriptError::SCRIPT_ERR_UNBALANCED_CONDITIONAL) if stack.size < 1
                    result = pop_bool
                    result = !result if opcode == OP_NOTIF
                  end
                  flow_stack << result
                when OP_ELSE
                  return set_error(ScriptError::SCRIPT_ERR_UNBALANCED_CONDITIONAL) if flow_stack.size < 1
                  flow_stack << !flow_stack.pop
                when OP_ENDIF
                  return set_error(ScriptError::SCRIPT_ERR_UNBALANCED_CONDITIONAL) if flow_stack.empty?
                  flow_stack.pop
                when OP_NOP
                when OP_NOP1, OP_NOP4..OP_NOP10
                  return set_error(ScriptError::SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS) if flag?(SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                when OP_CHECKLOCKTIMEVERIFY
                  return set_error(ScriptError::SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS) if flag?(SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  # TODO implement
                when OP_CHECKSEQUENCEVERIFY
                  return set_error(ScriptError::SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS) if flag?(SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  # TODO implement
                when OP_DUP
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << stack.last
                when OP_2DUP
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  2.times { stack << stack[-2] }
                when OP_3DUP
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 3
                  3.times { stack << stack[-3] }
                when OP_IFDUP
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << stack.last if cast_to_bool(stack.last)
                when OP_RIPEMD160
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << Digest::RMD160.hexdigest(pop_string.htb)
                when OP_SHA1
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << Digest::SHA1.hexdigest(pop_string.htb)
                when OP_SHA256
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << Digest::SHA256.hexdigest(pop_string.htb)
                when OP_HASH160
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << Bitcoin.hash160(pop_string)
                when OP_HASH256
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << Bitcoin.double_sha256(pop_string.htb).bth
                when OP_VERIFY
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  return set_error(ScriptError::SCRIPT_ERR_VERIFY) unless pop_bool
                when OP_TOALTSTACK
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  alt_stack << stack.pop
                when OP_FROMALTSTACK
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_ALTSTACK_OPERATION) if alt_stack.size < 1
                  stack << alt_stack.pop
                when OP_DROP
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack.pop
                when OP_2DROP
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  2.times { stack.pop }
                when OP_NIP
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  stack.delete_at(-2)
                when OP_OVER
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  stack << stack[-2]
                when OP_2OVER
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 4
                  2.times { stack << stack[-4]}
                when OP_PICK, OP_ROLL
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  pos = pop_int
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if pos < 0 || pos >= stack.size
                  stack << stack[-pos - 1]
                  stack.delete_at(-pos - 2) if opcode == OP_ROLL
                when OP_ROT
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 3
                  stack << stack[-3]
                  stack.delete_at(-4)
                when OP_2ROT
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 6
                  2.times { stack << stack[-6] }
                  2.times { stack.delete_at(-7) }
                when OP_SWAP
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  tmp = stack.last
                  stack[-1] = stack[-2]
                  stack[-2] = tmp
                when OP_2SWAP
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 4
                  2.times {stack << stack[-4]}
                  2.times {stack.delete_at(-5)}
                when OP_TUCK
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  stack.insert(-3, stack.last)
                when OP_ABS
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  v = pop_int
                  stack << v.abs
                when OP_BOOLAND
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  a, b = pop_int(2)
                  stack << ((!a.zero? && !b.zero?) ? 1 : 0)
                when OP_BOOLOR
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  a, b = pop_int(2)
                  stack << ((!a.zero? || !b.zero?) ? 1 : 0)
                when OP_NUMEQUAL, OP_NUMEQUALVERIFY
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  a, b = pop_int(2)
                  result = a == b
                  stack << (result ? 1 : 0)
                  if opcode == OP_NUMEQUALVERIFY
                    if result
                      stack.pop
                    else
                      return set_error(ScriptError::SCRIPT_ERR_NUMEQUALVERIFY)
                    end
                  end
                when OP_LESSTHAN, OP_LESSTHANOREQUAL
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  a, b = pop_int(2)
                  stack << (a < b ? 1 : 0) if opcode == OP_LESSTHAN
                  stack << (a <= b ? 1 : 0) if opcode == OP_LESSTHANOREQUAL
                when OP_GREATERTHAN, OP_GREATERTHANOREQUAL
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  a, b = pop_int(2)
                  stack << (a > b ? 1 : 0) if OP_GREATERTHAN
                  stack << (a >= b ? 1 : 0) if OP_GREATERTHANOREQUAL
                when OP_MIN
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  stack << pop_int(2).min
                when OP_MAX
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  stack << pop_int(2).max
                when OP_WITHIN
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 3
                  x, min, max = pop_int(3)
                  stack << ((min..max).include?(x) ? 1 : 0)
                when OP_NOT
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << (pop_int == 0 ? 1 : 0)
                when OP_SIZE
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  item = stack.last
                  item = Bitcoin::Script.encode_number(item) if item.is_a?(Numeric)
                  size = item.htb.bytesize
                  stack << size
                when OP_NEGATE
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << -pop_int
                when OP_NUMNOTEQUAL
                  return set_error(ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION)  if stack.size < 2
                  a, b = pop_int(2)
                  stack << (a == b ? 0 : 1)
                when OP_CODESEPARATOR
                  last_code_separator_index = index + 1
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

    # pop the item with the int value for the number specified by +count+ from the stack.
    def pop_int(count = 1)
      i = stack.pop(count).map do |s|
        case s
          when String
            Script.decode_number(s)
          else
            s
        end
      end
      count == 1 ? i.first : i
    end

    # pop the item with the string(hex) value for the number specified by +count+ from the stack.
    def pop_string(count = 1)
      s = stack.pop(count).map do |s|
        case s
          when Numeric
            Script.encode_number(s)
          else
            s
        end
      end
      count == 1 ? s.first : s
    end

    # pop the item with the boolean value from the stack.
    def pop_bool
      cast_to_bool(pop_string.htb)
    end

    # see https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp#L36-L49
    def cast_to_bool(v)
      case v
        when Numeric
          return v != 0
        when String
          v.each_byte.with_index do |b, i|
            return !(i == (v.bytesize - 1) && b == 0x80)  unless b == 0
          end
          false
        else
          false
      end
    end

  end

end