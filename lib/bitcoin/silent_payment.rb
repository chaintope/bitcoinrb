require 'set'

module Bitcoin
  # BIP-352 silent payment module.
  # @see https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki
  module SilentPayment
    autoload :Output, 'bitcoin/silent_payment/output'

    # Maximum number of silent payment addresses that can share the same scan public key
    # within a single transaction. This is the maximum number of P2TR outputs that can fit
    # within a 100KB transaction under current standardness rules.
    K_MAX = 2323
    
    # Derive payment point.
    #
    # @param [Array<Bitcoin::Script>] prevouts An array of previous output script.
    # @param [Array<Bitcoin::Key>] private_keys An array of Bitcoin::Key objects corresponding to each public key in prevouts.
    # @param [Array<Bech32::SilentPaymentAddr>] recipients
    # @return [Array<ECDSA::Point>] An array of derived points.
    # @raise [ArgumentError]
    def derive_payment_points(prevouts, private_keys, recipients)
      raise ArgumentError, "prevouts must be Array." unless prevouts.is_a? Array
      raise ArgumentError, "private_keys must be Array." unless private_keys.is_a? Array
      raise ArgumentError, "prevouts and private_keys must be the same length." unless prevouts.length == private_keys.length
      raise ArgumentError, "recipients must be Array." unless recipients.is_a? Array

      input_pub_keys = []
      field = ECDSA::PrimeField.new(Bitcoin::Secp256k1::GROUP.order)
      sum_priv_keys = 0
      prevouts.each_with_index do |prevout, index|
        key = private_keys[index]
        raise ArgumentError, "private_keys element must be Bitcoin::Key." unless key.is_a? Bitcoin::Key
        priv_key_int = key.priv_key.to_i(16)
        public_key = extract_public_key(prevout, inputs[index])
        next if public_key.nil?
        private_key = if public_key.p2tr? && key.to_point.y.odd?
                        field.mod(-priv_key_int)
                      else
                        priv_key_int
                      end
        input_pub_keys << public_key
        sum_priv_keys = field.mod(sum_priv_keys + private_key)
      end
      agg_pubkey = (Bitcoin::Secp256k1::GROUP.generator.to_jacobian * sum_priv_keys).to_affine
      return [] if agg_pubkey.infinity?

      outpoint_l = inputs.map{|i|i.out_point.to_hex}.sort.first

      input_hash = Bitcoin.tagged_hash("BIP0352/Inputs", outpoint_l.htb + agg_pubkey.to_hex.htb).bth

      destinations = {}
      recipients.each do |sp_addr|
        raise ArgumentError, "recipients element must be Bech32::SilentPaymentAddr." unless sp_addr.is_a? Bech32::SilentPaymentAddr
        destinations[sp_addr.scan_key] = [] unless destinations.has_key?(sp_addr.scan_key)
        destinations[sp_addr.scan_key] << sp_addr.spend_key
      end

      # Check K_max limit: fail if any group exceeds the limit
      destinations.each_value do |spends|
        raise ArgumentError, "Recipient group exceeds K_max limit (#{K_MAX})." if spends.length > K_MAX
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


    # Scan transaction outputs for silent payment outputs belonging to the receiver.
    #
    # @param [Array<Bitcoin::Script>] prevouts An array of previous output scripts corresponding to each input.
    # @param [Bitcoin::Key] scan_private_key The receiver's scan private key (b_scan).
    # @param [Bitcoin::Key] spend_pubkey The receiver's spend key. Pass a Key initialized with spend_priv_key to derive the public key.
    # @param [Array<Integer>] labels An array of label integers for labeled addresses (default: []).
    # @return [Array<Bitcoin::SilentPayment::Output>] An array of detected silent payment outputs.
    # @raise [ArgumentError] If any of the required parameters are invalid.
    def scan_sp_outputs(prevouts, scan_private_key, spend_pubkey, labels = [])
      raise ArgumentError, "prevouts must be Array." unless prevouts.is_a? Array
      raise ArgumentError, "scan_private_key must be Bitcoin::Key." unless scan_private_key.is_a? Bitcoin::Key
      raise ArgumentError, "spend_pubkey must be Bitcoin::Key." unless spend_pubkey.is_a? Bitcoin::Key

      has_taproot = !outputs.find{|o| o.script_pubkey.p2tr? }.nil?
      return [] unless has_taproot
      sum_pub_keys = Bitcoin::Secp256k1::GROUP.infinity.to_jacobian
      maximum_witness_version = Bitcoin::Opcodes.opcode_to_small_int(Bitcoin::Opcodes::OP_1)
      prevouts.each.with_index do |prevout, index|
        return [] if prevout.witness_program? && prevout.witness_data.first > maximum_witness_version

        public_key = extract_public_key(prevout, inputs[index])
        next if public_key.nil?
        sum_pub_keys += public_key.to_point.to_jacobian
      end
      return [] if sum_pub_keys.infinity?

      field = ECDSA::PrimeField.new(Bitcoin::Secp256k1::GROUP.order)
      outpoint_l = inputs.map{|i|i.out_point.to_hex}.sort.first
      input_hash = Bitcoin.tagged_hash("BIP0352/Inputs", outpoint_l.htb + sum_pub_keys.to_affine.to_hex.htb).bth
      ecdh_shared_secret = (sum_pub_keys * field.mod(input_hash.to_i(16) * scan_private_key.priv_key.to_i(16))).to_affine.to_hex.htb

      # Pre-compute label tweak points with their label values and scalar tweaks
      label_tweaks = labels.map do |m|
        label_tweak = Bitcoin.tagged_hash('BIP0352/Label', scan_private_key.priv_key.htb + [m].pack('N'))
        label_point = Bitcoin::Secp256k1::GROUP.generator.to_jacobian * label_tweak.bti
        [m, label_tweak, label_point]
      end

      k = 0
      results = []
      found_outputs = Set.new
      loop do
        # Stop scanning if K_max limit is reached
        break if k == K_MAX

        t_k = Bitcoin.tagged_hash('BIP0352/SharedSecret', ecdh_shared_secret + [k].pack('N'))
        p_k = Bitcoin::Secp256k1::GROUP.generator.to_jacobian * t_k.bti + spend_pubkey.to_point.to_jacobian
        found = false
        outputs.each do |output|
          next unless output.script_pubkey.p2tr?
          next if found_outputs.include?(output)
          output_pubkey = Bitcoin::Key.from_xonly_pubkey(output.script_pubkey.witness_data[1].bth)

          # Check basic match (no label)
          if p_k.to_affine.x == output_pubkey.to_point.x
            results << SilentPayment::Output.new(output, t_k)
            found_outputs << output
            k += 1
            found = true
            break
          end

          # Check labeled matches
          label_tweaks.each do |label_value, label_tweak_scalar, label_point|
            p_k_labeled = p_k + label_point
            if p_k_labeled.to_affine.x == output_pubkey.to_point.x
              # Full tweak is t_k + label_tweak (mod order)
              full_tweak = field.mod(t_k.bti + label_tweak_scalar.bti).to_s(16).rjust(64, '0').htb
              results << SilentPayment::Output.new(output, full_tweak, label_value)
              found_outputs << output
              k += 1
              found = true
              break
            end
          end
          break if found
        end
        break unless found
      end
      results
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