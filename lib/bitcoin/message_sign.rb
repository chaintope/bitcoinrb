module Bitcoin

  module MessageSign

    class Error < StandardError; end

    module_function

    FORMAT_LEGACY = :legacy
    FORMAT_SIMPLE = :simple
    FORMAT_FULL = :full

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
      sig = case format
            when FORMAT_LEGACY
              key.sign_compact(digest)
            else
              validate_address!(address)
              addr = Bitcoin::Script.parse_from_addr(address)
              sig_ver, algo = if addr.p2wpkh?
                                [:witness_v0, :ecdsa]
                              elsif addr.p2tr?
                                [:taproot, :schnorr]
                              else
                                raise ArgumentError "#{address} dose not supported."
                              end
              tx = to_sign_tx(digest, address)
              prev_out = Bitcoin::TxOut.new(script_pubkey: addr)
              sighash = tx.sighash_for_input(0, addr, sig_version: sig_ver, amount: 0, prevouts: [prev_out])
              sig = key.sign(sighash, algo: algo) + [Bitcoin::SIGHASH_TYPE[:all]].pack('C')
              tx.in[0].script_witness.stack << sig
              tx.in[0].script_witness.stack << key.pubkey.htb
              format == FORMAT_SIMPLE ? tx.in[0].script_witness.to_payload : tx.to_payload
            end
      Base64.strict_encode64(sig)
    end

    # Verify a signed message.
    # @param [String] address Signer's bitcoin address, it must refer to a public key.
    # @param [String] signature The signature in base64 format.
    # @param [String] message The message that was signed.
    # @return [Boolean] Verification result.
    def verify_message(address, signature, message, prefix: Bitcoin.chain_params.message_magic)
      addr_script = Bitcoin::Script.parse_from_addr(address)
      begin
        sig = Base64.strict_decode64(signature)
      rescue ArgumentError
        raise ArgumentError, 'Invalid signature'
      end
      if addr_script.p2pkh?
        begin
          # Legacy verification
          pubkey = Bitcoin::Key.recover_compact(message_hash(message, prefix: prefix, legacy: true), sig)
          return false unless pubkey
          pubkey.to_p2pkh == address
        rescue RuntimeError
          return false
        end
      elsif addr_script.witness_program?
        # BIP322 verification
        tx = to_sign_tx(message_hash(message, prefix: prefix, legacy: false), address)
        tx.in[0].script_witness = Bitcoin::ScriptWitness.parse_from_payload(sig)
        script_pubkey = Bitcoin::Script.parse_from_addr(address)
        tx_out = Bitcoin::TxOut.new(script_pubkey: script_pubkey)
        flags = Bitcoin::STANDARD_SCRIPT_VERIFY_FLAGS
        interpreter = Bitcoin::ScriptInterpreter.new(flags: flags, checker: Bitcoin::TxChecker.new(tx: tx, input_index: 0, prevouts: [tx_out]))
        interpreter.verify_script(Bitcoin::Script.new, script_pubkey, tx.in[0].script_witness)
      else
        raise ArgumentError, "This address unsupported."
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
      script = Bitcoin::Script.parse_from_addr(address)
      raise ArgumentError, 'This address unsupported' if script.p2sh? || script.p2wsh?
    end

    def validate_format!(format)
      unless [FORMAT_LEGACY, FORMAT_FULL, FORMAT_SIMPLE].include?(format)
        raise ArgumentError "Invalid format specified."
      end
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

    private_class_method :validate_address!
    private_class_method :validate_format!
  end
end
