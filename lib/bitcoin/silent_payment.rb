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
    # @return [Array<ECDSA::Point>] An array of derived points, one per recipient in the same order.
    # @raise [ArgumentError]
    def derive_payment_points(prevouts, private_keys, recipients)
      raise ArgumentError, "prevouts must be Array." unless prevouts.is_a? Array
      raise ArgumentError, "private_keys must be Array." unless private_keys.is_a? Array
      raise ArgumentError, "prevouts and private_keys must be the same length." unless prevouts.length == private_keys.length
      raise ArgumentError, "recipients must be Array." unless recipients.is_a? Array

      field = ECDSA::PrimeField.new(Bitcoin::Secp256k1::GROUP.order)
      plain_seckeys = []
      taproot_seckeys = []
      sum_priv_keys = 0
      prevouts.each_with_index do |prevout, index|
        key = private_keys[index]
        raise ArgumentError, "private_keys element must be Bitcoin::Key." unless key.is_a? Bitcoin::Key
        public_key = extract_public_key(prevout, inputs[index])
        next if public_key.nil?
        priv_key_int = key.priv_key.to_i(16)
        if public_key.p2tr?
          taproot_seckeys << key.priv_key
          priv_key_int = field.mod(-priv_key_int) unless key.to_point.has_even_y?
        else
          plain_seckeys << key.priv_key
        end
        sum_priv_keys = field.mod(sum_priv_keys + priv_key_int)
      end
      return [] if plain_seckeys.empty? && taproot_seckeys.empty?
      # The input private keys sum to zero, so the aggregate public key is the point at infinity
      # and no shared secret exists.
      return [] if sum_priv_keys.zero?

      destinations = recipients.map do |sp_addr|
        raise ArgumentError, "recipients element must be Bech32::SilentPaymentAddr." unless sp_addr.is_a? Bech32::SilentPaymentAddr
        [sp_addr.scan_key, sp_addr.spend_key]
      end
      destinations.group_by(&:first).each_value do |group|
        raise ArgumentError, "Recipient group exceeds K_max limit (#{K_MAX})." if group.length > K_MAX
      end

      Bitcoin.secp_impl.sp_create_outputs(
        destinations, sp_outpoint_smallest,
        plain_seckeys: plain_seckeys, taproot_seckeys: taproot_seckeys
      ).map { |xonly| Bitcoin::Key.from_xonly_pubkey(xonly).to_point }
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

      taproot_outputs = outputs.select{|o| o.script_pubkey.p2tr? }
      return [] if taproot_outputs.empty?

      plain_pubkeys = []
      xonly_pubkeys = []
      sum_pub_keys = Bitcoin::Secp256k1::GROUP.infinity.to_jacobian
      maximum_witness_version = Bitcoin::Opcodes.opcode_to_small_int(Bitcoin::Opcodes::OP_1)
      prevouts.each.with_index do |prevout, index|
        return [] if prevout.witness_program? && prevout.witness_data.first > maximum_witness_version

        public_key = extract_public_key(prevout, inputs[index])
        next if public_key.nil?
        if public_key.p2tr?
          xonly_pubkeys << public_key.xonly_pubkey
        else
          plain_pubkeys << public_key.pubkey
        end
        sum_pub_keys += public_key.to_point.to_jacobian
      end
      return [] if plain_pubkeys.empty? && xonly_pubkeys.empty?
      # Not a silent payment transaction, so there is nothing to find. Checked here rather than
      # left to the implementation, which reports it as an error.
      return [] if sum_pub_keys.infinity?

      impl = Bitcoin.secp_impl
      label_values = {}
      label_tweaks = {}
      labels.each do |m|
        label, tweak = impl.sp_create_label(scan_private_key.priv_key, m)
        label_values[label] = m
        label_tweaks[label] = tweak
      end

      tx_outputs = taproot_outputs.map{|o| o.script_pubkey.witness_data[1].bth }
      impl.sp_scan_outputs(tx_outputs, scan_private_key.priv_key, sp_outpoint_smallest, spend_pubkey.pubkey,
                           plain_pubkeys: plain_pubkeys, xonly_pubkeys: xonly_pubkeys,
                           labels: label_tweaks).map do |found|
        tx_out = taproot_outputs[tx_outputs.index(found[:output])]
        SilentPayment::Output.new(tx_out, found[:tweak].htb, found[:label] && label_values[found[:label]])
      end
    end

    # The lexicographically smallest outpoint of this tx's inputs, which the input hash of
    # BIP-352 commits to.
    # @return [String] The outpoint with hex format(36 bytes).
    def sp_outpoint_smallest
      inputs.map{|i| i.out_point.to_hex }.min
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