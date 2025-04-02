module Bitcoin
  module SilentPayment


    # Derive payment
    # @param [Array] prevouts An array of previous output script(Bitcoin::Script).
    # @param [Array] private_keys An array of private key corresponding to each public key in prevouts.
    # @param [Array] recipients
    # @return [Array]
    # @raise [ArgumentError]
    def derive_payment_points(prevouts, private_keys, recipients)
      raise ArgumentError, "prevouts must be Array." unless prevouts.is_a? Array
      raise ArgumentError, "private_keys must be Array." unless private_keys.is_a? Array
      raise ArgumentError, "prevouts and private_keys must be the same length." unless prevouts.length == private_keys.length
      raise ArgumentError, "recipients must be Array." unless recipients.is_a? Array

      outpoint_l = inputs.map{|i|i.out_point.to_hex}.sort.first

      input_pub_keys = []
      field = ECDSA::PrimeField.new(Bitcoin::Secp256k1::GROUP.order)
      sum_priv_keys = 0
      prevouts.each_with_index do |prevout, index|
        k = Bitcoin::Key.new(priv_key: private_keys[index].to_s(16))
        public_key = extract_public_key(prevout, inputs[index])
        next if public_key.nil?
        private_key = if public_key.p2tr? && k.to_point.y.odd?
                        field.mod(-private_keys[index])
                      else
                        private_keys[index]
                      end
        input_pub_keys << public_key
        sum_priv_keys = field.mod(sum_priv_keys + private_key)
      end
      agg_pubkey = (Bitcoin::Secp256k1::GROUP.generator.to_jacobian * sum_priv_keys).to_affine
      return [] if agg_pubkey.infinity?

      input_hash = Bitcoin.tagged_hash("BIP0352/Inputs", outpoint_l.htb + agg_pubkey.to_hex.htb).bth

      destinations = {}
      recipients.each do |sp_addr|
        raise ArgumentError, "recipients element must be Bech32::SilentPaymentAddr." unless sp_addr.is_a? Bech32::SilentPaymentAddr
        destinations[sp_addr.scan_key] = [] unless destinations.has_key?(sp_addr.scan_key)
        destinations[sp_addr.scan_key] << sp_addr.spend_key
      end
      outputs = []
      destinations.each do |scan_key, spends|
        scan_key = Bitcoin::Key.new(pubkey: scan_key).to_point.to_jacobian
        ecdh_shared_secret = (scan_key * field.mod(input_hash.to_i(16) * sum_priv_keys)).to_affine.to_hex.htb
        spends.each.with_index do |spend, i|
          t_k = Bitcoin.tagged_hash('BIP0352/SharedSecret', ecdh_shared_secret + [i].pack('N'))
          spend_key = Bitcoin::Key.new(pubkey: spend).to_point.to_jacobian
          outputs << (spend_key + Bitcoin::Secp256k1::GROUP.generator.to_jacobian * t_k.bth.to_i(16)).to_affine
        end
      end
      outputs
    end

    # Extract public keys from +prevout+ and input.
    def extract_public_key(prevout, input)
      if prevout.p2pkh?
        spk_hash = prevout.chunks[2].pushed_data.bth
        input.script_sig.chunks.reverse.each do |chunk|
          next unless chunk.pushdata?
          pubkey = chunk.pushed_data.bth
          if Bitcoin.hash160(pubkey) == spk_hash
            return Bitcoin::Key.new(pubkey: pubkey) if pubkey.htb.bytesize == Bitcoin::Key::COMPRESSED_PUBLIC_KEY_SIZE
          end
        end
      elsif prevout.p2sh?
        redeem_script = Bitcoin::Script.parse_from_payload(input.script_sig.chunks.last.pushed_data)
        if redeem_script.p2wpkh?
          pk = input.script_witness.stack.last
          return Bitcoin::Key.new(pubkey: pk.bth) if pk.bytesize == Bitcoin::Key::COMPRESSED_PUBLIC_KEY_SIZE
        end
      elsif prevout.p2wpkh?
        pk = input.script_witness.stack.last
        return Bitcoin::Key.new(pubkey: pk.bth) if pk.bytesize == Bitcoin::Key::COMPRESSED_PUBLIC_KEY_SIZE
      elsif prevout.p2tr?
        witness_stack = input.script_witness.stack.dup
        witness_stack.pop if witness_stack.last.bth.start_with?("50")
        if witness_stack.length > 1
          # script-path
          cb = Bitcoin::Taproot::ControlBlock.parse_from_payload(witness_stack.last)
          return nil if cb.internal_key == Bitcoin::Taproot::NUMS_H
        end
        pubkey = Bitcoin::Key.from_xonly_pubkey(prevout.chunks[1].pushed_data.bth)
        return pubkey if pubkey.compressed?
      end
      nil
    end
  end
end