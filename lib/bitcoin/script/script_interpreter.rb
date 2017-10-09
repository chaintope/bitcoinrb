module Bitcoin

  class ScriptInterpreter

    include Bitcoin::Opcodes

    attr_reader :stack
    attr_reader :debug
    attr_reader :flags
    attr_accessor :error
    attr_reader :checker
    attr_reader :require_minimal

    DISABLE_OPCODES = [OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_INVERT, OP_AND, OP_OR, OP_XOR, OP_2MUL, OP_2DIV, OP_DIV, OP_MUL, OP_MOD, OP_LSHIFT, OP_RSHIFT]

    # initialize runner
    def initialize(flags: [], checker: TxChecker.new)
      @stack, @debug = [], []
      @flags = flags
      @checker = checker
      @require_minimal = flag?(SCRIPT_VERIFY_MINIMALDATA)
    end

    # eval script
    # @param [Bitcoin::Script] script_sig a signature script (unlock script which data push only)
    # @param [Bitcoin::Script] script_pubkey a script pubkey (locking script)
    # @param [Bitcoin::ScriptWitness] witness a witness script
    # @return [Boolean] result
    def verify_script(script_sig, script_pubkey, witness = ScriptWitness.new)

      return set_error(SCRIPT_ERR_SIG_PUSHONLY) if flag?(SCRIPT_VERIFY_SIGPUSHONLY) && !script_sig.push_only?

      stack_copy = nil
      had_witness = false

      return false unless eval_script(script_sig, :base)

      stack_copy = stack.dup if flag?(SCRIPT_VERIFY_P2SH)

      return false unless eval_script(script_pubkey, :base)

      return set_error(SCRIPT_ERR_EVAL_FALSE) if stack.empty? || !cast_to_bool(stack.last.htb)

      # Bare witness programs
      if flag?(SCRIPT_VERIFY_WITNESS) && script_pubkey.witness_program?
        had_witness = true
        return set_error(SCRIPT_ERR_WITNESS_MALLEATED) unless script_sig.size == 0
        version, program = script_pubkey.witness_data
        stack_copy = stack.dup
        return false unless verify_witness_program(witness, version, program)
      end

      # Additional validation for spend-to-script-hash transactions
      if flag?(SCRIPT_VERIFY_P2SH) && script_pubkey.p2sh?
        return set_error(SCRIPT_ERR_SIG_PUSHONLY) unless script_sig.push_only?
        tmp = stack
        @stack = stack_copy
        raise 'stack cannot be empty.' if stack.empty?
        begin
          redeem_script = Bitcoin::Script.parse_from_payload(stack.pop.htb)
        rescue Exception => e
          return set_error(SCRIPT_ERR_BAD_OPCODE, "Failed to parse serialized redeem script for P2SH. #{e.message}")
        end
        return false unless eval_script(redeem_script, :base)
        return set_error(SCRIPT_ERR_EVAL_FALSE) if stack.empty? || !cast_to_bool(stack.last)

        # P2SH witness program
        if flag?(SCRIPT_VERIFY_WITNESS) && redeem_script.witness_program?
          had_witness = true
          # The scriptSig must be _exactly_ a single push of the redeemScript. Otherwise we reintroduce malleability.
          return set_error(SCRIPT_ERR_WITNESS_MALLEATED_P2SH) unless script_sig == (Bitcoin::Script.new << redeem_script.to_payload.bth)

          version, program = redeem_script.witness_data
          return false unless verify_witness_program(witness, version, program)
        end
      end

      # The CLEANSTACK check is only performed after potential P2SH evaluation,
      # as the non-P2SH evaluation of a P2SH script will obviously not result in a clean stack (the P2SH inputs remain).
      # The same holds for witness evaluation.
      if flag?(SCRIPT_VERIFY_CLEANSTACK)
        # Disallow CLEANSTACK without P2SH, as otherwise a switch CLEANSTACK->P2SH+CLEANSTACK would be possible,
        # which is not a softfork (and P2SH should be one).
        raise 'assert' unless flag?(SCRIPT_VERIFY_P2SH)
        return set_error(SCRIPT_ERR_CLEANSTACK) unless stack.size == 1
      end

      if flag?(SCRIPT_VERIFY_WITNESS)
        raise 'assert' unless flag?(SCRIPT_VERIFY_P2SH)
        return set_error(SCRIPT_ERR_WITNESS_UNEXPECTED) if !had_witness && !witness.empty?
      end

      true
    end

    def set_error(err_code, extra_message = nil)
      @error = ScriptError.new(err_code, extra_message)
      false
    end

    def verify_witness_program(witness, version, program)
      if version == 0
        if program.bytesize == 32
          return set_error(SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY) if witness.stack.size == 0
          script_pubkey = Bitcoin::Script.parse_from_payload(witness.stack.last)
          @stack = witness.stack[0..-2].map{|w|w.bth}
          script_hash = Bitcoin.sha256(script_pubkey.to_payload)
          return set_error(SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH) unless script_hash == program
        elsif program.bytesize == 20
          return set_error(SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH) unless witness.stack.size == 2
          script_pubkey = Bitcoin::Script.to_p2pkh(program.bth)
          @stack = witness.stack.map{|w|w.bth}
        else
          return set_error(SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH)
        end
      elsif flag?(SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
        return set_error(SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
      else
        return true # Higher version witness scripts return true for future softfork compatibility
      end

      stack.each do |s| # Disallow stack item size > MAX_SCRIPT_ELEMENT_SIZE in witness stack
        return set_error(SCRIPT_ERR_PUSH_SIZE) if s.htb.bytesize > MAX_SCRIPT_ELEMENT_SIZE
      end

      return false unless eval_script(script_pubkey, :witness_v0)

      return set_error(SCRIPT_ERR_EVAL_FALSE) unless stack.size == 1
      return set_error(SCRIPT_ERR_EVAL_FALSE) unless cast_to_bool(stack.last)
      true
    end

    def eval_script(script, sig_version)
      return set_error(SCRIPT_ERR_SCRIPT_SIZE) if script.size > MAX_SCRIPT_SIZE
      begin
        flow_stack = []
        alt_stack = []
        last_code_separator_index = 0
        op_count = 0

        script.chunks.each_with_index do |c, index|
          need_exec = !flow_stack.include?(false)

          return set_error(SCRIPT_ERR_PUSH_SIZE) if c.pushdata? && c.pushed_data.bytesize > MAX_SCRIPT_ELEMENT_SIZE

          opcode = c.opcode

          if need_exec && c.pushdata?
            if require_minimal && !minimal_push?(c.pushed_data, opcode)
              return set_error(SCRIPT_ERR_MINIMALDATA)
            end
            return set_error(SCRIPT_ERR_BAD_OPCODE) unless verify_pushdata_length(c)
            stack << c.pushed_data.bth
          else
            if opcode > OP_16 && (op_count += 1) > MAX_OPS_PER_SCRIPT
              return set_error(SCRIPT_ERR_OP_COUNT)
            end
            return set_error(SCRIPT_ERR_DISABLED_OPCODE) if DISABLE_OPCODES.include?(opcode)
            next unless (need_exec || (OP_IF <= opcode && opcode <= OP_ENDIF))
            small_int = Opcodes.opcode_to_small_int(opcode)
            if small_int && opcode != OP_0
              push_int(small_int)
            else
              case opcode
                when OP_0
                  stack << ''
                when OP_DEPTH
                  push_int(stack.size)
                when OP_EQUAL, OP_EQUALVERIFY
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  a, b = pop_string(2)
                  result = a == b
                  push_int(result ? 1 : 0)
                  if opcode == OP_EQUALVERIFY
                    if result
                      stack.pop
                    else
                      return set_error(SCRIPT_ERR_EQUALVERIFY)
                    end
                  end
                when OP_0NOTEQUAL
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  push_int(pop_int == 0 ? 0 : 1)
                when OP_ADD
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  a, b = pop_int(2)
                  push_int(a + b)
                when OP_1ADD
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  push_int(pop_int + 1)
                when OP_SUB
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  a, b = pop_int(2)
                  push_int(a - b)
                when OP_1SUB
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  push_int(pop_int - 1)
                when OP_IF, OP_NOTIF
                  result = false
                  if need_exec
                    return set_error(SCRIPT_ERR_UNBALANCED_CONDITIONAL) if stack.size < 1
                    value = pop_string.htb
                    if sig_version == :witness_v0 && flag?(SCRIPT_VERIFY_MINIMALIF)
                      if value.bytesize > 1 || (value.bytesize == 1 && value[0].unpack('C').first != 1)
                        return set_error(SCRIPT_ERR_MINIMALIF)
                      end
                    end
                    result = cast_to_bool(value)
                    result = !result if opcode == OP_NOTIF
                  end
                  flow_stack << result
                when OP_ELSE
                  return set_error(SCRIPT_ERR_UNBALANCED_CONDITIONAL) if flow_stack.size < 1
                  flow_stack << !flow_stack.pop
                when OP_ENDIF
                  return set_error(SCRIPT_ERR_UNBALANCED_CONDITIONAL) if flow_stack.empty?
                  flow_stack.pop
                when OP_NOP
                when OP_NOP1, OP_NOP4..OP_NOP10
                  return set_error(SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS) if flag?(SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                when OP_CHECKLOCKTIMEVERIFY
                  unless flag?(SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)
                    return set_error(SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS) if flag?(SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                    next
                  end
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  # Note that elsewhere numeric opcodes are limited to operands in the range -2**31+1 to 2**31-1,
                  # however it is legal for opcodes to produce results exceeding that range.
                  # This limitation is implemented by CScriptNum's default 4-byte limit.
                  # If we kept to that limit we'd have a year 2038 problem,
                  # even though the nLockTime field in transactions themselves is uint32 which only becomes meaningless after the year 2106.
                  # Thus as a special case we tell CScriptNum to accept up to 5-byte bignums,
                  # which are good until 2**39-1, well beyond the 2**32-1 limit of the nLockTime field itself.
                  locktime = cast_to_int(stack.last, 5)
                  return set_error(SCRIPT_ERR_NEGATIVE_LOCKTIME) if locktime < 0
                  return set_error(SCRIPT_ERR_UNSATISFIED_LOCKTIME) unless checker.check_locktime(locktime)
                when OP_CHECKSEQUENCEVERIFY
                  unless flag?(SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)
                    if flag?(SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                      return set_error(SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS)
                    end
                    next
                  end
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1

                  # nSequence, like nLockTime, is a 32-bit unsigned integer field.
                  # See the comment in CHECKLOCKTIMEVERIFY regarding 5-byte numeric operands.
                  sequence = cast_to_int(stack.last, 5)

                  # In the rare event that the argument may be < 0 due to some arithmetic being done first,
                  # you can always use 0 MAX CHECKSEQUENCEVERIFY.
                  return set_error(SCRIPT_ERR_NEGATIVE_LOCKTIME) if sequence < 0

                  # To provide for future soft-fork extensibility,
                  # if the operand has the disabled lock-time flag set, CHECKSEQUENCEVERIFY behaves as a NOP.
                  next if (sequence & Bitcoin::TxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0

                  # Compare the specified sequence number with the input.
                  unless checker.check_sequence(sequence)
                    return set_error(SCRIPT_ERR_UNSATISFIED_LOCKTIME)
                  end
                when OP_DUP
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << stack.last
                when OP_2DUP
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  2.times { stack << stack[-2] }
                when OP_3DUP
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 3
                  3.times { stack << stack[-3] }
                when OP_IFDUP
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << stack.last if cast_to_bool(stack.last)
                when OP_RIPEMD160
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << Digest::RMD160.hexdigest(pop_string.htb)
                when OP_SHA1
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << Digest::SHA1.hexdigest(pop_string.htb)
                when OP_SHA256
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << Digest::SHA256.hexdigest(pop_string.htb)
                when OP_HASH160
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << Bitcoin.hash160(pop_string)
                when OP_HASH256
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack << Bitcoin.double_sha256(pop_string.htb).bth
                when OP_VERIFY
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  return set_error(SCRIPT_ERR_VERIFY) unless pop_bool
                when OP_TOALTSTACK
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  alt_stack << stack.pop
                when OP_FROMALTSTACK
                  return set_error(SCRIPT_ERR_INVALID_ALTSTACK_OPERATION) if alt_stack.size < 1
                  stack << alt_stack.pop
                when OP_DROP
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  stack.pop
                when OP_2DROP
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  2.times { stack.pop }
                when OP_NIP
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  stack.delete_at(-2)
                when OP_OVER
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  stack << stack[-2]
                when OP_2OVER
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 4
                  2.times { stack << stack[-4]}
                when OP_PICK, OP_ROLL
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  pos = pop_int
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if pos < 0 || pos >= stack.size
                  stack << stack[-pos - 1]
                  stack.delete_at(-pos - 2) if opcode == OP_ROLL
                when OP_ROT
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 3
                  stack << stack[-3]
                  stack.delete_at(-4)
                when OP_2ROT
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 6
                  2.times { stack << stack[-6] }
                  2.times { stack.delete_at(-7) }
                when OP_SWAP
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  tmp = stack.last
                  stack[-1] = stack[-2]
                  stack[-2] = tmp
                when OP_2SWAP
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 4
                  2.times {stack << stack[-4]}
                  2.times {stack.delete_at(-5)}
                when OP_TUCK
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  stack.insert(-3, stack.last)
                when OP_ABS
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  v = pop_int
                  push_int(v.abs)
                when OP_BOOLAND
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  a, b = pop_int(2)
                  push_int((!a.zero? && !b.zero?) ? 1 : 0)
                when OP_BOOLOR
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  a, b = pop_int(2)
                  push_int((!a.zero? || !b.zero?) ? 1 : 0)
                when OP_NUMEQUAL, OP_NUMEQUALVERIFY
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  a, b = pop_int(2)
                  result = a == b
                  push_int(result ? 1 : 0)
                  if opcode == OP_NUMEQUALVERIFY
                    if result
                      stack.pop
                    else
                      return set_error(SCRIPT_ERR_NUMEQUALVERIFY)
                    end
                  end
                when OP_LESSTHAN, OP_LESSTHANOREQUAL
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  a, b = pop_int(2)
                  push_int(a < b ? 1 : 0) if opcode == OP_LESSTHAN
                  push_int(a <= b ? 1 : 0) if opcode == OP_LESSTHANOREQUAL
                when OP_GREATERTHAN, OP_GREATERTHANOREQUAL
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  a, b = pop_int(2)
                  push_int(a > b ? 1 : 0) if opcode == OP_GREATERTHAN
                  push_int(a >= b ? 1 : 0) if opcode == OP_GREATERTHANOREQUAL
                when OP_MIN
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  push_int(pop_int(2).min)
                when OP_MAX
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 2
                  push_int(pop_int(2).max)
                when OP_WITHIN
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 3
                  x, a, b = pop_int(3)
                  push_int((a <= x && x < b) ? 1 : 0)
                when OP_NOT
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  push_int(pop_int == 0 ? 1 : 0)
                when OP_SIZE
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  item = stack.last
                  item = Bitcoin::Script.encode_number(item) if item.is_a?(Numeric)
                  size = item.htb.bytesize
                  push_int(size)
                when OP_NEGATE
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < 1
                  push_int(-pop_int)
                when OP_NUMNOTEQUAL
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION)  if stack.size < 2
                  a, b = pop_int(2)
                  push_int(a == b ? 0 : 1)
                when OP_CODESEPARATOR
                  last_code_separator_index = index + 1
                when OP_CHECKSIG, OP_CHECKSIGVERIFY
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION)  if stack.size < 2
                  sig, pubkey = pop_string(2)

                  subscript = script.subscript(last_code_separator_index..-1)
                  if sig_version == :base
                    subscript = subscript.find_and_delete(Script.new << sig)
                  end

                  return false if !check_pubkey_encoding(pubkey, sig_version) || !check_signature_encoding(sig) # error already set.

                  success = checker.check_sig(sig, pubkey, subscript, sig_version)

                  # https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki#NULLFAIL
                  if !success && flag?(SCRIPT_VERIFY_NULLFAIL) && sig.bytesize > 0
                    return set_error(SCRIPT_ERR_SIG_NULLFAIL)
                  end

                  push_int(success ? 1 : 0)

                  if opcode == OP_CHECKSIGVERIFY
                    if success
                      stack.pop
                    else
                      return set_error(SCRIPT_ERR_CHECKSIGVERIFY)
                    end
                  end
                when OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION)  if stack.size < 1
                  pubkey_count = pop_int
                  unless (0..MAX_PUBKEYS_PER_MULTISIG).include?(pubkey_count)
                    return set_error(SCRIPT_ERR_PUBKEY_COUNT)
                  end

                  op_count += pubkey_count
                  return set_error(SCRIPT_ERR_OP_COUNT) if op_count > MAX_OPS_PER_SCRIPT

                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < pubkey_count

                  pubkeys = pop_string(pubkey_count)
                  pubkeys = [pubkeys] if pubkeys.is_a?(String)

                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION)  if stack.size < 1

                  sig_count = pop_int
                  return set_error(SCRIPT_ERR_SIG_COUNT) if sig_count < 0 || sig_count > pubkey_count
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION) if stack.size < (sig_count)

                  sigs = pop_string(sig_count)
                  sigs = [sigs] if sigs.is_a?(String)
                  
                  subscript = script.subscript(last_code_separator_index..-1)

                  if sig_version == :base
                    sigs.each do |sig|
                      subscript = subscript.find_and_delete(Script.new << sig)
                    end
                  end

                  success = true
                  while success && sig_count > 0
                    sig = sigs.pop
                    pubkey = pubkeys.pop
                    return false if !check_pubkey_encoding(pubkey, sig_version) || !check_signature_encoding(sig) # error already set.
                    ok = checker.check_sig(sig, pubkey, subscript, sig_version)
                    if ok
                      sig_count -= 1
                    else
                      sigs << sig
                    end
                    pubkey_count -= 1
                    success = false if sig_count > pubkey_count
                  end

                  if !success && flag?(SCRIPT_VERIFY_NULLFAIL)
                    sigs.each do |sig|
                      # If the operation failed, we require that all signatures must be empty vector
                      return set_error(SCRIPT_ERR_SIG_NULLFAIL) if sig.bytesize > 0
                    end
                  end

                  # A bug causes CHECKMULTISIG to consume one extra argument whose contents were not checked in any way.
                  # Unfortunately this is a potential source of mutability,
                  # so optionally verify it is exactly equal to zero prior to removing it from the stack.
                  return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION)  if stack.size < 1
                  if flag?(SCRIPT_VERIFY_NULLDUMMY) && stack[-1].size > 0
                    return set_error(SCRIPT_ERR_SIG_NULLDUMMY)
                  end
                  stack.pop

                  push_int(success ? 1 : 0)
                  if opcode == OP_CHECKMULTISIGVERIFY
                    if success
                      stack.pop
                    else
                      return set_error(SCRIPT_ERR_CHECKMULTISIGVERIFY)
                    end
                  end
                when OP_RETURN
                  return set_error(SCRIPT_ERR_OP_RETURN)
                else
                  return set_error(SCRIPT_ERR_BAD_OPCODE)
              end
            end
          end

          # max stack size check
          return set_error(SCRIPT_ERR_STACK_SIZE) if stack.size + alt_stack.size > MAX_STACK_SIZE
        end
      rescue Exception => e
        puts e
        puts e.backtrace
        return set_error(SCRIPT_ERR_UNKNOWN_ERROR, e.message)
      end

      return set_error(SCRIPT_ERR_UNBALANCED_CONDITIONAL) unless flow_stack.empty?

      set_error(SCRIPT_ERR_OK)
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
      i = stack.pop(count).map{ |s| cast_to_int(s) }
      count == 1 ? i.first : i
    end

    # cast item to int value.
    def cast_to_int(s, max_num_size = DEFAULT_MAX_NUM_SIZE)
      data = s.htb
      raise '"script number overflow"' if data.bytesize > max_num_size
      if require_minimal && data.bytesize > 0
        if data.bytes[-1] & 0x7f == 0 && (data.bytesize <= 1 || data.bytes[data.bytesize - 2] & 0x80 == 0)
          raise 'non-minimally encoded script number'
        end
      end
      Script.decode_number(s)
    end

    # push +i+ into stack as encoded by Script#encode_number
    def push_int(i)
      stack << Script.encode_number(i)
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
            return !(i == (v.bytesize - 1) && b == 0x80) unless b == 0
          end
          false
        else
          false
      end
    end

    def check_signature_encoding(sig)
      return true if sig.size.zero?
      if (flag?(SCRIPT_VERIFY_DERSIG) || flag?(SCRIPT_VERIFY_LOW_S) || flag?(SCRIPT_VERIFY_STRICTENC)) && !Key.valid_signature_encoding?(sig.htb)
        return set_error(SCRIPT_ERR_SIG_DER)
      elsif flag?(SCRIPT_VERIFY_LOW_S) && !low_der_signature?(sig)
        return false
      elsif flag?(SCRIPT_VERIFY_STRICTENC) && !defined_hashtype_signature?(sig)
        return set_error(SCRIPT_ERR_SIG_HASHTYPE)
      end
      true
    end

    def low_der_signature?(sig)
      return set_error(SCRIPT_ERR_SIG_DER) unless Key.valid_signature_encoding?(sig.htb)
      return set_error(SCRIPT_ERR_SIG_HIGH_S) unless Key.low_signature?(sig.htb)
      true
    end

    def defined_hashtype_signature?(signature)
      sig = signature.htb
      return false if sig.empty?
      s = sig.unpack('C*')
      hash_type = s[-1] & (~(SIGHASH_TYPE[:anyonecanpay]))
      return false if hash_type < SIGHASH_TYPE[:all] || hash_type > SIGHASH_TYPE[:single]
      true
    end

    def check_pubkey_encoding(pubkey, sig_version)
      if flag?(SCRIPT_VERIFY_STRICTENC) && !Key.compress_or_uncompress_pubkey?(pubkey)
        return set_error(SCRIPT_ERR_PUBKEYTYPE)
      end
      # Only compressed keys are accepted in segwit
      if flag?(SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) &&
          sig_version == :witness_v0 && !Key.compress_pubkey?(pubkey)
        return set_error(SCRIPT_ERR_WITNESS_PUBKEYTYPE)
      end
      true
    end

    def minimal_push?(data, opcode)
      if data.bytesize.zero?
        return opcode == OP_0
      elsif data.bytesize == 1 && data.bytes[0] >= 1 && data.bytes[0] <= 16
        return opcode == OP_1 + (data.bytes[0] - 1)
      elsif data.bytesize == 1 && data.bytes[0] == 0x81
        return opcode == OP_1NEGATE
      elsif data.bytesize <= 75
        return opcode == data.bytesize
      elsif data.bytesize <= 255
        return opcode == OP_PUSHDATA1
      elsif data.bytesize <= 65535
        return opcode == OP_PUSHDATA2
      end
      true
    end

    def verify_pushdata_length(chunk)
      buf = StringIO.new(chunk)
      opcode = buf.read(1).ord
      offset = 1
      len = case opcode
              when OP_PUSHDATA1
                offset += 1
                buf.read(1).unpack('C').first
              when OP_PUSHDATA2
                offset += 2
                buf.read(2).unpack('v').first
              when OP_PUSHDATA4
                offset += 4
                buf.read(4).unpack('V').first
              else
                opcode
            end
      chunk.bytesize == len + offset
    end

  end

end