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
          key_type = buf.read(1).unpack1('C')
          key = buf.read(key_len - 1)
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
            input.sighash_type = value.unpack1('I')
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
            raise ArgumentError, 'Duplicate Key, key for proprietary value already provided.' if input.proprietaries.any?{|p| p.key == key}
            input.proprietaries << Proprietary.new(key, value)
          when PSBT_IN_TYPES[:tap_key_sig]
            raise ArgumentError, 'Size of key was not the expected size for the type tap key sig' unless key_len == 1
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
              input.tap_leaf_scripts[cb] = value.bth
            rescue Bitcoin::Taproot::Error => e
              raise ArgumentError, e.message
            end
          when PSBT_IN_TYPES[:tap_bip32_derivation]
            raise ArgumentError, 'Duplicate Key, key for tap bip32 derivation value already provided.' if input.tap_bip32_derivations[key.bth]
            raise ArgumentError, 'Size of key was not the expected size for the type tap bip32 derivation' unless key.bytesize == X_ONLY_PUBKEY_SIZE
            input.tap_bip32_derivations[key.bth] = value.bth
          when PSBT_IN_TYPES[:tap_internal_key]
            raise ArgumentError, 'Size of key was not the expected size for the type tap internal key' unless key_len == 1
            raise ArgumentError, 'Invalid x-only public key size for the type tap internal key' unless value.bytesize == X_ONLY_PUBKEY_SIZE
            input.tap_internal_key = value.bth
          when PSBT_IN_TYPES[:tap_merkle_root]
            raise ArgumentError, 'Size of key was not the expected size for the type tap merkle root' unless key_len == 1
            raise ArgumentError, 'Invalid merkle root hash size for the type tap merkle root' unless value.bytesize == 32
            input.tap_merkle_root = value.bth
          else
            unknown_key = ([key_type].pack('C') + key).bth
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
        if final_script_sig.nil? && final_script_witness.nil?
          payload << partial_sigs.map{|k, v|PSBT.serialize_to_vector(PSBT_IN_TYPES[:partial_sig], key: k.htb, value: v)}.join
          payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:sighash], value: [sighash_type].pack('I')) if sighash_type
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
        end
        payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:script_sig], value: final_script_sig.to_payload) if final_script_sig
        payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:script_witness], value: final_script_witness.to_payload) if final_script_witness
        payload << proprietaries.map(&:to_payload).join
        payload << unknowns.map {|k,v|Bitcoin.pack_var_int(k.htb.bytesize) << k.htb << Bitcoin.pack_var_int(v.bytesize) << v}.join
        payload << PSBT_SEPARATOR.itb
        payload
      end

      # Check whether input's scriptPubkey is correct witness.
      # @return [Boolean]
      def valid_witness_input?
        return true if witness_utxo&.script_pubkey.p2wpkh? # P2WPKH
        return true if witness_utxo&.script_pubkey.p2wsh? && witness_utxo&.script_pubkey == redeem_script.to_p2wsh # P2WSH
        # segwit nested in P2SH
        if witness_utxo&.script_pubkey.p2sh? && redeem_script&.witness_program? && redeem_script.to_p2sh == witness_utxo&.script_pubkey
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
        raise ArgumentError, 'The Partially Signed Input\'s non_witness_utxo are different.' unless non_witness_utxo == psbi.non_witness_utxo
        raise ArgumentError, 'The Partially Signed Input\'s witness_utxo are different.' unless witness_utxo == psbi.witness_utxo
        raise ArgumentError, 'The Partially Signed Input\'s sighash_type are different.' if sighash_type && psbi.sighash_type && sighash_type != psbi.sighash_type
        raise ArgumentError, 'The Partially Signed Input\'s redeem_script are different.' unless redeem_script == psbi.redeem_script
        raise ArgumentError, 'The Partially Signed Input\'s witness_script are different.' unless witness_script == psbi.witness_script
        combined = Bitcoin::PSBT::Input.new(non_witness_utxo: non_witness_utxo, witness_utxo: witness_utxo)
        combined.unknowns = Hash[unknowns.merge(psbi.unknowns).sort]
        combined.redeem_script = redeem_script
        combined.witness_script = witness_script
        combined.sighash_type = sighash_type
        sigs = Hash[partial_sigs.merge(psbi.partial_sigs)]
        redeem_script.get_multisig_pubkeys.each{|pubkey|combined.partial_sigs[pubkey.bth] = sigs[pubkey.bth]} if redeem_script&.multisig?
        witness_script.get_multisig_pubkeys.each{|pubkey|combined.partial_sigs[pubkey.bth] = sigs[pubkey.bth]} if witness_script&.multisig?
        combined.hd_key_paths = hd_key_paths.merge(psbi.hd_key_paths)
        combined
      end

      # finalize input.
      # TODO This feature is experimental and support only multisig.
      # @return [Bitcoin::PSBT::Input] finalized input.
      def finalize!
        if non_witness_utxo
          self.final_script_sig = Bitcoin::Script.new << Bitcoin::Opcodes::OP_0 if redeem_script.multisig?
          partial_sigs.values.each {|sig|final_script_sig << sig}
          final_script_sig << redeem_script.to_hex
          self.partial_sigs = {}
          self.hd_key_paths = {}
          self.redeem_script = nil
          self.sighash_type = nil
        else
          if redeem_script
            self.final_script_sig = Bitcoin::Script.parse_from_payload(Bitcoin::Script.pack_pushdata(redeem_script.to_payload))
            self.redeem_script = nil
          end
          if witness_script
            self.final_script_witness = Bitcoin::ScriptWitness.new
            final_script_witness.stack << '' if witness_script.multisig?
            partial_sigs.values.each {|sig| final_script_witness.stack << sig}
            final_script_witness.stack << witness_script.to_payload
            self.witness_script = nil
          end
          self.sighash_type = nil
          self.partial_sigs = {}
          self.hd_key_paths = {}
        end
        self
      end

      def to_h
        h = {}
        h[:non_witness_utxo] = non_witness_utxo.to_h if non_witness_utxo
        h[:witness_utxo] = witness_utxo.to_h if witness_utxo
        h[:redeem_script] = redeem_script.to_h if redeem_script
        h[:witness_script] = witness_script.to_h if redeem_script
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

    end

  end
end