module Bitcoin

  module PSBT

    # Class for PSBTs which contain per-input information
    class Input

      attr_accessor :non_witness_utxo # Bitcoin::Tx
      attr_accessor :witness_utxo # Bitcoin::TxOut
      attr_accessor :redeem_script
      attr_accessor :witness_script
      attr_accessor :final_script_sig
      attr_accessor :final_script_witness
      attr_accessor :hd_key_paths
      attr_accessor :partial_sigs
      attr_accessor :sighash_type
      attr_accessor :ripemd160_preimages
      attr_accessor :sha256_preimages
      attr_accessor :hash160_preimages
      attr_accessor :hash256_preimages
      attr_accessor :proprietaries
      attr_accessor :tap_key_sig
      attr_accessor :tap_script_sigs
      attr_accessor :tap_leaf_scripts
      attr_accessor :tap_bip32_derivations
      attr_accessor :tap_internal_key
      attr_accessor :tap_merkle_root
      attr_accessor :unknowns

      def initialize(non_witness_utxo: nil, witness_utxo: nil)
        @non_witness_utxo = non_witness_utxo
        @witness_utxo = witness_utxo
        @partial_sigs = {}
        @hd_key_paths = {}
        @ripemd160_preimages = {}
        @sha256_preimages = {}
        @hash160_preimages = {}
        @hash256_preimages = {}
        @proprietaries = []
        @tap_script_sigs = {}
        @tap_leaf_scripts = {}
        @tap_bip32_derivations = {}
        @unknowns = {}
      end

      # parse PSBT input data form buffer.
      # @param [StringIO] buf psbt buffer.
      # @return [Bitcoin::PSBTInput] psbt input.
      def self.parse_from_buf(buf)
        input = self.new
        found_sep = false
        until buf.eof?
          key_len = Bitcoin.unpack_var_int_from_io(buf)
          if key_len == 0
            found_sep = true
            break
          end
          key_start = buf.pos
          key_type = Bitcoin.unpack_var_int_from_io(buf)
          key = buf.read(key_len - (buf.pos - key_start))
          value = buf.read(Bitcoin.unpack_var_int_from_io(buf))

          case key_type
          when PSBT_IN_TYPES[:non_witness_utxo]
            raise ArgumentError, 'Invalid non-witness utxo typed key.' unless key_len == 1
            raise ArgumentError, 'Duplicate Key, input non-witness utxo already provided.' if input.non_witness_utxo
            input.non_witness_utxo = Bitcoin::Tx.parse_from_payload(value, strict: true)
          when PSBT_IN_TYPES[:witness_utxo]
            raise ArgumentError, 'Invalid input witness utxo typed key.' unless key_len == 1
            raise ArgumentError, 'Duplicate Key, input witness utxo already provided.' if input.witness_utxo
            input.witness_utxo = Bitcoin::TxOut.parse_from_payload(value)
          when PSBT_IN_TYPES[:partial_sig]
            if key.size != Bitcoin::Key::PUBLIC_KEY_SIZE && key.size != Bitcoin::Key::COMPRESSED_PUBLIC_KEY_SIZE
              raise ArgumentError, 'Size of key was not the expected size for the type partial signature pubkey.'
            end
            pubkey = Bitcoin::Key.new(pubkey: key.bth)
            raise ArgumentError, Errors::Messages::INVALID_PUBLIC_KEY unless pubkey.fully_valid_pubkey?
            raise ArgumentError, 'Duplicate Key, input partial signature for pubkey already provided.' if input.partial_sigs[pubkey.pubkey]
            input.partial_sigs[pubkey.pubkey] = value
          when PSBT_IN_TYPES[:sighash]
            raise ArgumentError, 'Invalid input sighash type typed key.' unless key_len == 1
            raise ArgumentError, 'Duplicate Key, input sighash type already provided.' if input.sighash_type
            raise ArgumentError, 'Invalid input sighash type value.' unless value.bytesize == 4
            input.sighash_type = value.unpack1('V')
          when PSBT_IN_TYPES[:redeem_script]
            raise ArgumentError, 'Invalid redeemscript typed key.' unless key_len == 1
            raise ArgumentError, 'Duplicate Key, input redeemScript already provided.' if input.redeem_script
            input.redeem_script = Bitcoin::Script.parse_from_payload(value)
          when PSBT_IN_TYPES[:witness_script]
            raise ArgumentError, 'Invalid witnessscript typed key.' unless key_len == 1
            raise ArgumentError, 'Duplicate Key, input witnessScript already provided.' if input.witness_script
            input.witness_script = Bitcoin::Script.parse_from_payload(value)
          when PSBT_IN_TYPES[:bip32_derivation]
            raise ArgumentError, 'Invalid bip32 typed key.' unless key_len
            raise ArgumentError, 'Duplicate Key, pubkey derivation path already provided.' if input.hd_key_paths[key.bth]
            input.hd_key_paths[key.bth] = Bitcoin::PSBT::HDKeyPath.new(key, Bitcoin::PSBT::KeyOriginInfo.parse_from_payload(value))
          when PSBT_IN_TYPES[:script_sig]
            raise ArgumentError, 'Invalid final scriptsig typed key.' unless key_len == 1
            raise ArgumentError, 'Duplicate Key, input final scriptSig already provided.' if input.final_script_sig
            input.final_script_sig = Bitcoin::Script.parse_from_payload(value)
          when PSBT_IN_TYPES[:script_witness]
            raise ArgumentError, 'Invalid final script witness typed key.' unless key_len == 1
            raise ArgumentError, 'Duplicate Key, input final scriptWitness already provided.' if input.final_script_witness
            input.final_script_witness = Bitcoin::ScriptWitness.parse_from_payload(value)
          when PSBT_IN_TYPES[:ripemd160]
            raise ArgumentError, 'Size of key was not the expected size for the type ripemd160 preimage' unless key.bytesize == RIPEMD160_SIZE
            raise ArgumentError, 'Duplicate Key, input ripemd160 preimage already provided' if input.ripemd160_preimages[key.bth]
            input.ripemd160_preimages[key.bth] = value.bth
          when PSBT_IN_TYPES[:sha256]
            raise ArgumentError, 'Size of key was not the expected size for the type sha256 preimage' unless key.bytesize == SHA256_SIZE
            raise ArgumentError, 'Duplicate Key, input sha256 preimage already provided' if input.sha256_preimages[key.bth]
            input.sha256_preimages[key.bth] = value.bth
          when PSBT_IN_TYPES[:hash160]
            raise ArgumentError, 'Size of key was not the expected size for the type hash160 preimage' unless key.bytesize == HASH160_SIZE
            raise ArgumentError, 'Duplicate Key, input hash160 preimage already provided' if input.hash160_preimages[key.bth]
            input.hash160_preimages[key.bth] = value.bth
          when PSBT_IN_TYPES[:hash256]
            raise ArgumentError, 'Size of key was not the expected size for the type hash256 preimage' unless key.bytesize == HASH256_SIZE
            raise ArgumentError, 'Duplicate Key, input hash256 preimage already provided' if input.hash256_preimages[key.bth]
            input.hash256_preimages[key.bth] = value.bth
          when PSBT_IN_TYPES[:proprietary]
            proprietary = Proprietary.new(key, value)
            raise ArgumentError, 'Duplicate Key, key for proprietary value already provided.' if input.proprietaries.any?{|p| p.key == proprietary.key}
            input.proprietaries << proprietary
          when PSBT_IN_TYPES[:tap_key_sig]
            raise ArgumentError, 'Size of key was not the expected size for the type tap key sig' unless key_len == 1
            raise ArgumentError, 'Duplicate Key, input tap key sig already provided.' if input.tap_key_sig
            raise ArgumentError, 'Invalid schnorr signature size for the type tap key sig' unless [64, 65].include?(value.bytesize)
            input.tap_key_sig = value.bth
          when PSBT_IN_TYPES[:tap_script_sig]
            raise ArgumentError, 'Duplicate Key, key for tap script sig value already provided.' if input.tap_script_sigs[key.bth]
            raise ArgumentError, 'Size of key was not the expected size for the type tap script sig' unless key.bytesize == (X_ONLY_PUBKEY_SIZE + 32)
            raise ArgumentError, 'Invalid schnorr signature size for the type tap script sig' unless [64, 65].include?(value.bytesize)
            input.tap_script_sigs[key.bth] = value.bth
          when PSBT_IN_TYPES[:tap_leaf_script]
            begin
              cb = Bitcoin::Taproot::ControlBlock.parse_from_payload(key)
              raise ArgumentError, 'Duplicate Key, key for tap leaf script value already provided.' if input.tap_leaf_scripts[cb]
              raise ArgumentError, 'Tap leaf script value must have a leaf version.' if value.bytesize < 1
              input.tap_leaf_scripts[cb] = value.bth
            rescue Bitcoin::Taproot::Error => e
              raise ArgumentError, e.message
            end
          when PSBT_IN_TYPES[:tap_bip32_derivation]
            raise ArgumentError, 'Duplicate Key, key for tap bip32 derivation value already provided.' if input.tap_bip32_derivations[key.bth]
            raise ArgumentError, 'Size of key was not the expected size for the type tap bip32 derivation' unless key.bytesize == X_ONLY_PUBKEY_SIZE
            PSBT.validate_tap_bip32_derivation!(value)
            input.tap_bip32_derivations[key.bth] = value.bth
          when PSBT_IN_TYPES[:tap_internal_key]
            raise ArgumentError, 'Size of key was not the expected size for the type tap internal key' unless key_len == 1
            raise ArgumentError, 'Duplicate Key, input tap internal key already provided.' if input.tap_internal_key
            raise ArgumentError, 'Invalid x-only public key size for the type tap internal key' unless value.bytesize == X_ONLY_PUBKEY_SIZE
            input.tap_internal_key = value.bth
          when PSBT_IN_TYPES[:tap_merkle_root]
            raise ArgumentError, 'Size of key was not the expected size for the type tap merkle root' unless key_len == 1
            raise ArgumentError, 'Duplicate Key, input tap merkle root already provided.' if input.tap_merkle_root
            raise ArgumentError, 'Invalid merkle root hash size for the type tap merkle root' unless value.bytesize == 32
            input.tap_merkle_root = value.bth
          else
            unknown_key = (Bitcoin.pack_var_int(key_type) + key).bth
            raise ArgumentError, 'Duplicate Key, key for unknown value already provided.' if input.unknowns[unknown_key]
            input.unknowns[unknown_key] = value
          end
        end
        raise ArgumentError, 'Separator is missing at the end of an input map.' unless found_sep
        input
      end

      def to_payload
        payload = ''
        payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:non_witness_utxo], value:
            (witness_utxo && valid_witness_input?) ? non_witness_utxo.serialize_old_format : non_witness_utxo.to_payload) if non_witness_utxo
        payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:witness_utxo], value: witness_utxo.to_payload) if witness_utxo
        payload << partial_sigs.map{|k, v|PSBT.serialize_to_vector(PSBT_IN_TYPES[:partial_sig], key: k.htb, value: v)}.join
        payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:sighash], value: [sighash_type].pack('V')) if sighash_type
        payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:redeem_script], value: redeem_script.to_payload) if redeem_script
        payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:witness_script], value: witness_script.to_payload) if witness_script
        payload << hd_key_paths.values.map(&:to_payload).join
        payload << ripemd160_preimages.map{|k, v|PSBT.serialize_to_vector(PSBT_IN_TYPES[:ripemd160], key: k.htb, value: v.htb)}.join
        payload << sha256_preimages.map{|k, v|PSBT.serialize_to_vector(PSBT_IN_TYPES[:sha256], key: k.htb, value: v.htb)}.join
        payload << hash160_preimages.map{|k, v|PSBT.serialize_to_vector(PSBT_IN_TYPES[:hash160], key: k.htb, value: v.htb)}.join
        payload << hash256_preimages.map{|k, v|PSBT.serialize_to_vector(PSBT_IN_TYPES[:hash256], key: k.htb, value: v.htb)}.join
        payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:tap_key_sig], value: tap_key_sig.htb) if tap_key_sig
        payload << tap_script_sigs.map{|k, v| PSBT.serialize_to_vector(PSBT_IN_TYPES[:tap_script_sig], key: k.htb, value: v.htb)}.join
        payload << tap_leaf_scripts.map{|k, v| PSBT.serialize_to_vector(PSBT_IN_TYPES[:tap_leaf_script], key: k.to_payload, value: v.htb)}.join
        payload << tap_bip32_derivations.map{|k, v| PSBT.serialize_to_vector(PSBT_IN_TYPES[:tap_bip32_derivation], key: k.htb, value: v.htb)}.join
        payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:tap_internal_key], value: tap_internal_key.htb) if tap_internal_key
        payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:tap_merkle_root], value: tap_merkle_root.htb) if tap_merkle_root
        payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:script_sig], value: final_script_sig.to_payload) if final_script_sig
        payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:script_witness], value: final_script_witness.to_payload) if final_script_witness
        payload << proprietaries.map(&:to_payload).join
        payload << unknowns.map {|k,v|Bitcoin.pack_var_int(k.htb.bytesize) << k.htb << Bitcoin.pack_var_int(v.bytesize) << v}.join
        payload << PSBT_SEPARATOR.itb
        payload
      end

      # Get the previous output this input spends.
      # @param [Integer] index The index of the outpoint this input refers to.
      # @return [Bitcoin::TxOut] The previous output, or nil if this input does not carry it.
      def utxo(index)
        (non_witness_utxo ? non_witness_utxo.out[index] : nil) || witness_utxo
      end

      # Check whether input's scriptPubkey is correct witness.
      # @return [Boolean]
      def valid_witness_input?
        return false unless witness_utxo
        return true if witness_utxo.script_pubkey.p2wpkh? # P2WPKH
        # P2WSH. The scriptPubkey commits to the witness script directly, so a redeem script is not used.
        return true if witness_utxo.script_pubkey.p2wsh? && witness_script &&
          Bitcoin::Script.to_p2wsh(witness_script) == witness_utxo.script_pubkey
        # segwit nested in P2SH
        if witness_utxo.script_pubkey.p2sh? && redeem_script&.witness_program? && redeem_script.to_p2sh == witness_utxo.script_pubkey
          return true if redeem_script.p2wpkh?# nested p2wpkh
          return true if witness_script&.to_sha256 == redeem_script.witness_data[1].bth # nested p2wsh
        end
        false
      end

      # Check whether input's scriptPubkey is correct witness.
      # @return [Boolean]
      def valid_non_witness_input?(utxo)
        utxo.script_pubkey.p2sh? && redeem_script.to_p2sh == utxo.script_pubkey
      end

      # Check whether the signer can sign this input.
      # @param [Bitcoin::TxOut] utxo utxo object which input refers.
      # @return [Boolean]
      def ready_to_sign?(utxo)
        return valid_witness_input? if witness_utxo
        valid_non_witness_input?(utxo) # non_witness_utxo
      end

      # Checks whether a PSBTInput is already signed.
      # @return [Boolean] return true if already signed.
      def signed?
        final_script_sig || final_script_witness
      end

      # add signature as partial sig.
      # @param [String] pubkey a public key with hex format.
      # @param [String] sig a signature.
      def add_sig(pubkey, sig)
        raise ArgumentError, 'The sighash in signature is invalid.' if sighash_type && sig.unpack('C*')[-1] != sighash_type
        raise ArgumentError, 'Duplicate Key, input partial signature for pubkey already provided.' if partial_sigs[pubkey]
        partial_sigs[pubkey] = sig
      end

      # merge two PSBT inputs to create one PSBT.
      # @param [Bitcoin::PSBT::Input] psbi PSBT input to be combined which must have same property in PSBT Input.
      # @return [Bitcoin::PSBT::Input] combined object.
      def merge(psbi)
        raise ArgumentError, 'The argument psbt must be an instance of Bitcoin::PSBT::Input.' unless psbi.is_a?(Bitcoin::PSBT::Input)
        field = ->(name) { PSBT.merge_field(send(name), psbi.send(name), "Input's #{name}") }
        combined = Bitcoin::PSBT::Input.new(non_witness_utxo: field.call(:non_witness_utxo), witness_utxo: field.call(:witness_utxo))
        # Fields which hold one value: present on one side, or equal on both.
        %i[redeem_script witness_script sighash_type final_script_sig final_script_witness
           tap_key_sig tap_internal_key tap_merkle_root].each do |name|
          combined.send("#{name}=", field.call(name))
        end
        # Maps: the union. For a key present on both sides this input's value is kept, as Bitcoin Core's
        # combiner inserts the other map into its own.
        combined.partial_sigs = merge_partial_sigs(psbi.partial_sigs)
        %i[hd_key_paths ripemd160_preimages sha256_preimages hash160_preimages hash256_preimages
           tap_script_sigs tap_leaf_scripts tap_bip32_derivations].each do |name|
          combined.send("#{name}=", psbi.send(name).merge(send(name)))
        end
        combined.proprietaries = PSBT.merge_proprietaries(proprietaries, psbi.proprietaries)
        combined.unknowns = Hash[psbi.unknowns.merge(unknowns).sort]
        combined
      end

      # Finalize this input, building the final scriptSig and witness from the partial signatures and scripts.
      # Supported: P2PKH, P2PK, bare multisig, P2WPKH, P2WSH and P2SH wrapping any of them. Anything else,
      # a missing script or too few signatures raises rather than producing an unspendable input.
      # @param [Integer] prevout_index The index of the output this input spends, used to look up the scriptPubKey
      #   in +non_witness_utxo+. Not needed when +witness_utxo+ or a redeem/witness script is present.
      # @return [Bitcoin::PSBT::Input] finalized input.
      # @raise [ArgumentError] If the input cannot be finalized.
      def finalize!(prevout_index = nil)
        return self if signed?
        script_pubkey = spent_script_pubkey(prevout_index)
        if script_pubkey.p2sh?
          raise ArgumentError, 'The redeem script is missing.' unless redeem_script
          raise ArgumentError, 'The redeem script does not match the scriptPubKey.' unless redeem_script.to_p2sh == script_pubkey
          if redeem_script.witness_program?
            self.final_script_witness = Bitcoin::ScriptWitness.new(witness_stack(redeem_script))
            self.final_script_sig = Bitcoin::Script.new << redeem_script.to_payload
          else
            self.final_script_sig = Bitcoin::Script.new
            satisfaction(redeem_script).each { |item| final_script_sig << item }
            final_script_sig << redeem_script.to_payload
          end
        elsif script_pubkey.witness_program?
          self.final_script_witness = Bitcoin::ScriptWitness.new(witness_stack(script_pubkey))
        else
          self.final_script_sig = Bitcoin::Script.new
          satisfaction(script_pubkey).each { |item| final_script_sig << item }
        end
        self.partial_sigs = {}
        self.hd_key_paths = {}
        self.redeem_script = nil
        self.witness_script = nil
        self.sighash_type = nil
        self
      end

      def to_h
        h = {}
        h[:non_witness_utxo] = non_witness_utxo.to_h if non_witness_utxo
        h[:witness_utxo] = witness_utxo.to_h if witness_utxo
        h[:redeem_script] = redeem_script.to_h if redeem_script
        h[:witness_script] = witness_script.to_h if witness_script
        h[:final_script_sig] = final_script_sig.to_h if final_script_sig
        h[:final_script_witness] = final_script_witness.to_h if final_script_witness
        h[:bip32_derivs] = hd_key_paths.values.map(&:to_h) unless hd_key_paths.empty?
        h[:partial_signatures] = partial_sigs.map {|k, v| {"#{k}": v.bth}} unless partial_sigs.empty?
        h[:sighash_type] = sighash_type if sighash_type
        h[:ripemd160_preimages] = ripemd160_preimages.map {|k, v| {"#{k}": v}} unless ripemd160_preimages.empty?
        h[:sha256_preimages] = sha256_preimages.map {|k, v| {"#{k}": v}} unless sha256_preimages.empty?
        h[:hash160_preimages] = hash160_preimages.map {|k, v| {"#{k}": v}} unless hash160_preimages.empty?
        h[:hash256_preimages] = hash256_preimages.map {|k, v| {"#{k}": v}} unless hash256_preimages.empty?
        h[:proprietary] = proprietaries.map(&:to_h) unless proprietaries.empty?
        h[:tap_key_sig] = tap_key_sig if tap_key_sig
        h[:tap_script_sig] = tap_script_sigs.map {|k, v| {"#{k}": v}} unless tap_script_sigs.empty?
        h[:tap_leaf_script] = tap_leaf_scripts.map {|k, v| {"#{k}": v}} unless tap_leaf_scripts.empty?
        h[:tap_bip32_derivs] = tap_bip32_derivations.map{|k, v| {"#{k}": v}} unless tap_bip32_derivations.empty?
        h[:tap_internal_key] = tap_internal_key if tap_internal_key
        h[:tap_merkle_root] = tap_merkle_root if tap_merkle_root
        h[:unknown] = unknowns.map {|k, v| {"#{k}": v.bth}} unless unknowns.empty?
        h
      end

      private

      # The union of the partial signatures of this input and +others+. Signatures for the keys of a multisig
      # redeem or witness script come first in the order of the script, which keeps the serialization stable,
      # and any other signature follows.
      # @param [Hash] others partial signatures of the other input.
      # @return [Hash]
      def merge_partial_sigs(others)
        sigs = others.merge(partial_sigs)
        script = [redeem_script, witness_script].compact.find(&:multisig?)
        return sigs unless script
        ordered = {}
        script.get_multisig_pubkeys.each { |pubkey| ordered[pubkey.bth] = sigs[pubkey.bth] if sigs[pubkey.bth] }
        ordered.merge(sigs)
      end

      # The scriptPubKey this input spends.
      # @param [Integer, nil] prevout_index The index of the output in +non_witness_utxo+.
      # @return [Bitcoin::Script]
      # @raise [ArgumentError] If it cannot be determined.
      def spent_script_pubkey(prevout_index)
        return witness_utxo.script_pubkey if witness_utxo
        if non_witness_utxo && prevout_index
          out = non_witness_utxo.out[prevout_index]
          raise ArgumentError, "non_witness_utxo does not have output #{prevout_index}." unless out
          return out.script_pubkey
        end
        # Without the utxo the scriptPubKey can still be inferred from the scripts.
        return redeem_script.to_p2sh if redeem_script
        return Bitcoin::Script.to_p2wsh(witness_script) if witness_script
        raise ArgumentError, 'The scriptPubKey of this input cannot be determined. Set witness_utxo, or non_witness_utxo and pass the prevout index.'
      end

      # The witness stack satisfying the witness program +program+.
      # @param [Bitcoin::Script] program A P2WPKH or P2WSH script.
      # @return [Array[String]] stack items with binary format.
      def witness_stack(program)
        if program.p2wpkh?
          satisfaction(program)
        elsif program.p2wsh?
          raise ArgumentError, 'The witness script is missing.' unless witness_script
          raise ArgumentError, 'The witness script does not match the witness program.' unless Bitcoin::Script.to_p2wsh(witness_script) == program
          satisfaction(witness_script) + [witness_script.to_payload]
        else
          raise ArgumentError, "Finalizing a witness program of this type is not supported: #{program}"
        end
      end

      # The stack items which satisfy +script+, built from the partial signatures.
      # @param [Bitcoin::Script] script A P2PKH, P2PK, P2WPKH or bare multisig script.
      # @return [Array[String]] items with binary format, in the order they are pushed.
      def satisfaction(script)
        if script.p2pkh? || script.p2wpkh?
          hash = (script.p2pkh? ? script.chunks[2] : script.chunks[1]).pushed_data.bth
          pubkey, sig = partial_sigs.find { |pk, _| Bitcoin.hash160(pk) == hash }
          raise ArgumentError, 'The partial signature for the key of this input is missing.' unless sig
          [sig, pubkey.htb]
        elsif script.p2pk?
          sig = partial_sigs[script.chunks[0].pushed_data.bth]
          raise ArgumentError, 'The partial signature for the key of this input is missing.' unless sig
          [sig]
        elsif script.multisig?
          # Signatures are pushed in the order of the keys in the script, which is what OP_CHECKMULTISIG requires,
          # and only as many as the threshold needs.
          threshold = Bitcoin::Opcodes.opcode_to_small_int(script.chunks[0].opcode)
          sigs = script.get_multisig_pubkeys.map { |pubkey| partial_sigs[pubkey.bth] }.compact
          raise ArgumentError, "Not enough signatures: #{threshold} required, #{sigs.size} present." if sigs.size < threshold
          [''] + sigs.first(threshold) # The empty item is consumed by the extra pop of OP_CHECKMULTISIG.
        else
          raise ArgumentError, "Finalizing a script of this type is not supported: #{script}"
        end
      end

    end

  end
end