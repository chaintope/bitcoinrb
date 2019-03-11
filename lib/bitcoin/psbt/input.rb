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
      attr_accessor :unknowns

      def initialize(non_witness_utxo: nil, witness_utxo: nil)
        @non_witness_utxo = non_witness_utxo
        @witness_utxo = witness_utxo
        @partial_sigs = {}
        @hd_key_paths = {}
        @unknowns = {}
      end

      # parse PSBT input data form buffer.
      # @param [StringIO] buf psbt buffer.
      # @return [Bitcoin::PSBTInput] psbt input.
      def self.parse_from_buf(buf)
        input = self.new
        until buf.eof?
          key_len = Bitcoin.unpack_var_int_from_io(buf)
          break if key_len == 0
          key_type = buf.read(1).unpack('C').first
          key = buf.read(key_len - 1)
          value = buf.read(Bitcoin.unpack_var_int_from_io(buf))

          case key_type
          when PSBT_IN_TYPES[:non_witness_utxo]
            raise ArgumentError, 'Invalid non-witness utxo typed key.' unless key_len == 1
            raise ArgumentError, 'Duplicate Key, input non-witness utxo already provided.' if input.non_witness_utxo
            input.non_witness_utxo = Bitcoin::Tx.parse_from_payload(value)
          when PSBT_IN_TYPES[:witness_utxo]
            raise ArgumentError, 'Invalid input witness utxo typed key.' unless key_len == 1
            raise ArgumentError, 'Duplicate Key, input witness utxo already provided.' if input.witness_utxo
            input.witness_utxo = Bitcoin::TxOut.parse_from_payload(value)
          when PSBT_IN_TYPES[:partial_sig]
            if key.size != Bitcoin::Key::PUBLIC_KEY_SIZE && key.size != Bitcoin::Key::COMPRESSED_PUBLIC_KEY_SIZE
              raise ArgumentError, 'Size of key was not the expected size for the type partial signature pubkey.'
            end
            pubkey = Bitcoin::Key.new(pubkey: key.bth)
            raise ArgumentError, 'Invalid pubkey.' unless pubkey.fully_valid_pubkey?
            raise ArgumentError, 'Duplicate Key, input partial signature for pubkey already provided.' if input.partial_sigs[pubkey.pubkey]
            input.partial_sigs[pubkey.pubkey] = value
          when PSBT_IN_TYPES[:sighash]
            raise ArgumentError, 'Invalid input sighash type typed key.' unless key_len == 1
            raise ArgumentError 'Duplicate Key, input sighash type already provided.' if input.sighash_type
            input.sighash_type = value.unpack('I').first
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
            input.hd_key_paths[key.bth] = Bitcoin::PSBT::HDKeyPath.parse_from_payload(key, value)
          when PSBT_IN_TYPES[:script_sig]
            raise ArgumentError, 'Invalid final scriptsig typed key.' unless key_len == 1
            raise ArgumentError, 'Duplicate Key, input final scriptSig already provided.' if input.final_script_sig
            input.final_script_sig = Bitcoin::Script.parse_from_payload(value)
          when PSBT_IN_TYPES[:script_witness]
            raise ArgumentError, 'Invalid final script witness typed key.' unless key_len == 1
            raise ArgumentError, 'Duplicate Key, input final scriptWitness already provided.' if input.final_script_witness
            input.final_script_witness = Bitcoin::ScriptWitness.parse_from_payload(value)
          else
            unknown_key = ([key_type].pack('C') + key).bth
            raise ArgumentError, 'Duplicate Key, key for unknown value already provided.' if input.unknowns[unknown_key]
            input.unknowns[unknown_key] = value
          end
        end
        input
      end

      def to_payload
        payload = ''
        payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:non_witness_utxo], value: non_witness_utxo.to_payload) if non_witness_utxo
        payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:witness_utxo], value: witness_utxo.to_payload) if witness_utxo
        if final_script_sig.nil? && final_script_witness.nil?
          payload << partial_sigs.map{|k, v|PSBT.serialize_to_vector(PSBT_IN_TYPES[:partial_sig], key: k.htb, value: v)}.join
          payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:sighash], value: [sighash_type].pack('I')) if sighash_type
          payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:redeem_script], value: redeem_script.to_payload) if redeem_script
          payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:witness_script], value: witness_script.to_payload) if witness_script
          payload << hd_key_paths.values.map(&:to_payload).join
        end
        payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:script_sig], value: final_script_sig.to_payload) if final_script_sig
        payload << PSBT.serialize_to_vector(PSBT_IN_TYPES[:script_witness], value: final_script_witness.to_payload) if final_script_witness
        payload << unknowns.map {|k,v|Bitcoin.pack_var_int(k.htb.bytesize) << k.htb << Bitcoin.pack_var_int(v.bytesize) << v}.join
        payload << PSBT_SEPARATOR.itb
        payload
      end

      # Sanity check
      def sane?
        return false if non_witness_utxo && witness_utxo
        return false if witness_script && witness_utxo.nil?
        return false if final_script_witness && witness_utxo.nil?
        true
      end

      # add signature as partial sig.
      # @param [String] pubkey a public key with hex format.
      # @param [String] sig a signature.
      def add_sig(pubkey, sig)
        raise ArgumentError, 'The sighash in signature is invalid.' unless sig.unpack('C*')[-1] == sighash_type
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
        raise ArgumentError, 'The Partially Signed Input\'s sighash_type are different.' unless sighash_type == psbi.sighash_type
        raise ArgumentError, 'The Partially Signed Input\'s redeem_script are different.' unless redeem_script == psbi.redeem_script
        raise ArgumentError, 'The Partially Signed Input\'s witness_script are different.' unless witness_script == psbi.witness_script
        combined = Bitcoin::PSBT::Input.new(non_witness_utxo: non_witness_utxo, witness_utxo: witness_utxo)
        combined.unknowns = unknowns.merge(psbi.unknowns)
        combined.redeem_script = redeem_script
        combined.witness_script = witness_script
        combined.sighash_type = sighash_type
        sigs = Hash[partial_sigs.merge(psbi.partial_sigs)]
        redeem_script.get_multisig_pubkeys.each{|pubkey|combined.partial_sigs[pubkey.bth] = sigs[pubkey.bth]} if redeem_script && redeem_script.multisig?
        witness_script.get_multisig_pubkeys.each{|pubkey|combined.partial_sigs[pubkey.bth] = sigs[pubkey.bth]} if witness_script && witness_script.multisig?
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
          final_script_sig << redeem_script.to_payload.bth
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

    end

  end
end