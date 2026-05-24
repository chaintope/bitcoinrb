module Bitcoin

  module MessageSign

    class Error < StandardError; end

    module_function

    FORMAT_LEGACY = :legacy
    FORMAT_SIMPLE = :simple
    FORMAT_FULL = :full

    # Prefix
    SIGNATURE_PREFIX_SIMPLE = 'smp'
    SIGNATURE_PREFIX_FULL = 'ful'
    SIGNATURE_PREFIX_POF = 'pof'

    # BIP-322 Required rules
    BIP322_VERIFY_FLAGS = [
      SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_DERSIG, SCRIPT_VERIFY_STRICTENC,
      SCRIPT_VERIFY_LOW_S, SCRIPT_VERIFY_NULLFAIL, SCRIPT_VERIFY_MINIMALDATA,
      SCRIPT_VERIFY_CLEANSTACK, SCRIPT_VERIFY_MINIMALIF,
      SCRIPT_VERIFY_CONST_SCRIPTCODE,
      SCRIPT_VERIFY_WITNESS, SCRIPT_VERIFY_TAPROOT,
      SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
      SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    ].inject(:|)

    # Sign a message.
    # @param [Bitcoin::Key] key Private key to sign.
    # @param [String] message The message to be signed.
    # @param [String] address An address of the key used for signing (required for full or simple format).
    # @param [String] format Format of signature data. Default is +FORMAT_LEGACY+.
    # @param [String] prefix (Optional) Prefix used in legacy format.
    # @return [String] Signature, base64 encoded.
    def sign_message(key, message, prefix: Bitcoin.chain_params.message_magic, format: FORMAT_LEGACY, address: nil)
      validate_format!(format)
      digest = message_hash(message, prefix: prefix, legacy: format == FORMAT_LEGACY)
      prefix_marker = ''
      sig = case format
            when FORMAT_LEGACY
              key.sign_compact(digest)
            else
              validate_address!(address)
              addr = Bitcoin::Script.parse_from_addr(address)
              sig_ver, algo = if addr.p2wpkh? || addr.p2wsh?
                                [:witness_v0, :ecdsa]
                              elsif addr.p2tr?
                                [:taproot, :schnorr]
                              else

                              end
              tx = to_sign_tx(digest, address)
              prev_out = Bitcoin::TxOut.new(script_pubkey: addr, value: 0)
              if addr.p2tr?
                sighash = tx.sighash_for_input(0, addr, sig_version: :taproot, prevouts: [prev_out], hash_type: Bitcoin::SIGHASH_TYPE[:default])
                tweaked = Bitcoin::Taproot.tweak_private_key(key, '')
                tx.in[0].script_witness.stack << tweaked.sign(sighash, algo: :schnorr)
              elsif addr.p2wpkh? || addr.p2wsh?
                sighash = tx.sighash_for_input(0, addr, sig_version: :witness_v0, amount: 0, prevouts: [prev_out])
                ecdsa  = key.sign(sighash, algo: :ecdsa) + [Bitcoin::SIGHASH_TYPE[:all]].pack('C')
                tx.in[0].script_witness.stack << ecdsa
                tx.in[0].script_witness.stack << key.pubkey.htb
              else
                raise ArgumentError, "#{address} dose not supported."
              end
              prefix_marker = format == FORMAT_SIMPLE ? SIGNATURE_PREFIX_SIMPLE : SIGNATURE_PREFIX_FULL
              format == FORMAT_SIMPLE ? tx.in[0].script_witness.to_payload : tx.to_payload
            end
      prefix_marker + Base64.strict_encode64(sig)
    end

    # Verify a signed message.
    # @param [String] address Signer's bitcoin address, it must refer to a public key.
    # @param [String] signature The signature in base64 format.
    # @param [String] message The message that was signed.
    # @return [Boolean] Verification result.
    def verify_message(address, signature, message, prefix: Bitcoin.chain_params.message_magic)
      addr_script = Bitcoin::Script.parse_from_addr(address)
      variant, body = case signature
                      when ''
                        raise ArgumentError, 'signature too short'
                      when /\A#{SIGNATURE_PREFIX_SIMPLE}/
                        [:simple, signature[3..]]
                      when /\A#{SIGNATURE_PREFIX_FULL}/
                        [:full, signature[3..]]
                      when /\A#{SIGNATURE_PREFIX_POF}/
                        [:pof, signature[3..]]
                      else
                        [:fallback, signature]
                      end
      begin
        payload = Base64.strict_decode64(body)
      rescue ArgumentError
        raise ArgumentError, 'Invalid signature'
      end

      case variant
      when :simple, :fallback
        return verify_legacy(address, payload, message, prefix: prefix) if addr_script.p2pkh?
        raise ArgumentError, 'simple format not supported for this address' unless
          addr_script.p2wpkh? || addr_script.p2wsh? || addr_script.p2tr?
        verify_simple(addr_script, payload, message, prefix: prefix)
      when :full
        begin
          tx = Bitcoin::Tx.parse_from_payload(payload)
        rescue StandardError
          raise ArgumentError, 'error parsing signature as full variant'
        end
        verify_full(addr_script, tx, message, prefix: prefix)
      when :pof
        raise NotImplementedError, 'proof of funds variant is not supported'
      else
        raise ArgumentError, "unknown signature variant: #{variant.inspect}"
      end
    end

    # Hashes a message for signing and verification.
    def message_hash(message, prefix: Bitcoin.chain_params.message_magic, legacy: true)
      if legacy
        Bitcoin.double_sha256(Bitcoin.pack_var_string(prefix) << Bitcoin.pack_var_string(message))
      else
        Bitcoin.tagged_hash('BIP0322-signed-message', message)
      end
    end

    def validate_address!(address)
      Bitcoin::Script.parse_from_addr(address)
    end

    def validate_format!(format)
      unless [FORMAT_LEGACY, FORMAT_FULL, FORMAT_SIMPLE].include?(format)
        raise ArgumentError "Invalid format specified."
      end
    end

    def validate_to_sign_tx!(tx)
      raise ArgumentError, "Invalid version." unless [0, 2].include?(tx.version)
      raise ArgumentError, "Multiple inputs (proof of funds) are not supported." unless tx.in.length == 1
      raise ArgumentError, "vin[0].prevout.n must be 0." unless tx.in[0].out_point.index == 0
      raise ArgumentError, "Multiple outputs are not supported." unless tx.out.length == 1
      raise ArgumentError, "vout[0].nValue must be 0." unless tx.out[0].value == 0
      raise ArgumentError, "vout[0].scriptPubKey must be OP_RETURN." unless tx.out[0].script_pubkey == Bitcoin::Script.new << Bitcoin::Opcodes::OP_RETURN
    end

    def to_spend_tx(digest, addr)
      validate_address!(addr)
      message_challenge = Bitcoin::Script.parse_from_addr(addr)
      tx = Bitcoin::Tx.new
      tx.version = 0
      tx.lock_time = 0
      prev_out = Bitcoin::OutPoint.create_coinbase_outpoint
      script_sig = Bitcoin::Script.new << Bitcoin::Opcodes::OP_0 << digest
      tx.in << Bitcoin::TxIn.new(out_point: prev_out, sequence: 0, script_sig: script_sig)
      tx.out << Bitcoin::TxOut.new(script_pubkey: message_challenge)
      tx
    end

    def to_sign_tx(digest, addr)
      tx = Bitcoin::Tx.new
      tx.version = 0
      tx.lock_time = 0
      prev_out = Bitcoin::OutPoint.from_txid(to_spend_tx(digest, addr).txid, 0)
      tx.in << Bitcoin::TxIn.new(out_point: prev_out, sequence: 0)
      tx.out << Bitcoin::TxOut.new(script_pubkey: Bitcoin::Script.new << Bitcoin::Opcodes::OP_RETURN)
      tx
    end

    def verify_simple(addr_script, witness_payload, message, prefix:)
      digest = message_hash(message, prefix: prefix, legacy: false)
      tx = to_sign_tx(digest, addr_script.to_addr)
      tx.in[0].script_witness = Bitcoin::ScriptWitness.parse_from_payload(witness_payload)
      run_interpreter(tx, addr_script)
    end

    def verify_full(addr_script, tx, message, prefix:)
      digest = message_hash(message, prefix: prefix, legacy: false)
      to_spend = to_spend_tx(digest, addr_script.to_addr)
      validate_to_sign_tx!(tx)
      return false unless tx.in[0].out_point.tx_hash == to_spend.tx_hash
      run_interpreter(tx, addr_script)
    end

    def run_interpreter(tx, script_pubkey)
      tx_out = Bitcoin::TxOut.new(script_pubkey: script_pubkey)
      checker = Bitcoin::TxChecker.new(tx: tx, input_index: 0, prevouts: [tx_out])
      interpreter = Bitcoin::ScriptInterpreter.new(flags: BIP322_VERIFY_FLAGS, checker: checker)
      interpreter.verify_script(tx.in[0].script_sig, script_pubkey, tx.in[0].script_witness)
    end

    def verify_legacy(address, sig_bytes, message, prefix:)
      pubkey = Bitcoin::Key.recover_compact(message_hash(message, prefix: prefix, legacy: true), sig_bytes)
      return false unless pubkey
      pubkey.to_p2pkh == address
    rescue StandardError
      false
    end

    private_class_method :validate_address!
    private_class_method :validate_format!
    private_class_method :validate_to_sign_tx!
    private_class_method :run_interpreter
    private_class_method :verify_simple
    private_class_method :verify_full
    private_class_method :verify_legacy
  end
end
