module Bitcoin

  module MessageSign

    class Error < StandardError; end

    module_function

    # Sign a message.
    # @param [Bitcoin::Key] key Private key to sign with.
    # @param [String] message The message to sign.
    # @return [String] Signature, base64 encoded.
    def sign_message(key, message, prefix: Bitcoin.chain_params.message_magic)
      digest = message_hash(message, prefix: prefix)
      compact_sig = key.sign_compact(digest)
      Base64.strict_encode64(compact_sig)
    end

    # Verify a signed message.
    # @param [String] address Signer's bitcoin address, it must refer to a public key.
    # @param [String] signature The signature in base64 format.
    # @param [String] message The message that was signed.
    # @return [Boolean] Verification result.
    def verify_message(address, signature, message, prefix: Bitcoin.chain_params.message_magic)
      sig = Base64.decode64(signature)
      raise ArgumentError, 'Invalid signature length' unless sig.bytesize == Bitcoin::Key::COMPACT_SIGNATURE_SIZE
      digest = message_hash(message, prefix: prefix)
      return false unless Bitcoin.valid_address?(address)
      pubkey = Bitcoin::Key.recover_compact(digest, sig)
      return false unless pubkey
      pubkey.to_p2pkh == address
    end

    # Hashes a message for signing and verification.
    def message_hash(message, prefix: Bitcoin.chain_params.message_magic)
      Bitcoin.double_sha256(Bitcoin.pack_var_string(prefix) << Bitcoin.pack_var_string(message))
    end

  end
end
