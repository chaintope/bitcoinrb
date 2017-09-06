module Bitcoin

  # bitcoin script error
  class ScriptError < Exception

    attr_accessor :code
    attr_accessor :extra_msg

    def initialize(code, extra_msg = '')
      raise 'invalid error code.' unless ERRCODES_MAP[code]
      @code = code
      @extra_msg = extra_msg
    end

    def to_s
      case code
      when SCRIPT_ERR_OK
        'No error'
      when SCRIPT_ERR_EVAL_FALSE
        'Script evaluated without error but finished with a false/empty top stack element'
      when SCRIPT_ERR_VERIFY
        'Script failed an OP_VERIFY operation'
      when SCRIPT_ERR_EQUALVERIFY
        'Script failed an OP_EQUALVERIFY operation'
      when SCRIPT_ERR_CHECKMULTISIGVERIFY
        'Script failed an OP_CHECKMULTISIGVERIFY operation'
      when SCRIPT_ERR_CHECKSIGVERIFY
        'Script failed an OP_CHECKSIGVERIFY operation'
      when SCRIPT_ERR_NUMEQUALVERIFY
        'Script failed an OP_NUMEQUALVERIFY operation'
      when SCRIPT_ERR_SCRIPT_SIZE
        'Script is too big'
      when SCRIPT_ERR_PUSH_SIZE
        'Push value size limit exceeded'
      when SCRIPT_ERR_OP_COUNT
        'Operation limit exceeded'
      when SCRIPT_ERR_STACK_SIZE
        'Stack size limit exceeded'
      when SCRIPT_ERR_SIG_COUNT
        'Signature count negative or greater than pubkey count'
      when SCRIPT_ERR_PUBKEY_COUNT
        'Pubkey count negative or limit exceeded'
      when SCRIPT_ERR_BAD_OPCODE
        'Opcode missing or not understood'
      when SCRIPT_ERR_DISABLED_OPCODE
        'Attempted to use a disabled opcode'
      when SCRIPT_ERR_INVALID_STACK_OPERATION
        'Operation not valid with the current stack size'
      when SCRIPT_ERR_INVALID_ALTSTACK_OPERATION
        'Operation not valid with the current altstack size'
      when SCRIPT_ERR_OP_RETURN
        'OP_was encountered'
      when SCRIPT_ERR_UNBALANCED_CONDITIONAL
        'Invalid OP_IF construction'
      when SCRIPT_ERR_NEGATIVE_LOCKTIME
        'Negative locktime'
      when SCRIPT_ERR_UNSATISFIED_LOCKTIME
        'Locktime requirement not satisfied'
      when SCRIPT_ERR_SIG_HASHTYPE
        'Signature hash type missing or not understood'
      when SCRIPT_ERR_SIG_DER
        'Non-canonical DER signature'
      when SCRIPT_ERR_MINIMALDATA
        'Data push larger than necessary'
      when SCRIPT_ERR_SIG_PUSHONLY
        'Only non-push operators allowed in signatures'
      when SCRIPT_ERR_SIG_HIGH_S
        'Non-canonical signature S value is unnecessarily high'
      when SCRIPT_ERR_SIG_NULLDUMMY
        'Dummy CHECKMULTISIG argument must be zero'
      when SCRIPT_ERR_MINIMALIF
        'OP_IF/NOTIF argument must be minimal'
      when SCRIPT_ERR_SIG_NULLFAIL
        'Signature must be zero for failed CHECK(MULTI)SIG operation'
      when SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS
        'NOPx reserved for soft-fork upgrades'
      when SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
        'Witness version reserved for soft-fork upgrades'
      when SCRIPT_ERR_PUBKEYTYPE
        'Public key is neither compressed or uncompressed'
      when SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH
        'Witness program has incorrect length'
      when SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY
        'Witness program was passed an empty witness'
      when SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH
        'Witness program hash mismatch'
      when SCRIPT_ERR_WITNESS_MALLEATED
        'Witness requires empty scriptSig'
      when SCRIPT_ERR_WITNESS_MALLEATED_P2SH
        'Witness requires only-redeemscript scriptSig'
      when SCRIPT_ERR_WITNESS_UNEXPECTED
        'Witness provided for non-witness script'
      when SCRIPT_ERR_WITNESS_PUBKEYTYPE
        'Using non-compressed keys in segwit'
      when SCRIPT_ERR_UNKNOWN_ERROR, SCRIPT_ERR_ERROR_COUNT
        'unknown error'
      else
        extra_msg ? extra_msg : 'unknown error'
      end
    end

    def self.name_to_code(name)
      NAME_MAP[name]
    end

  end
end