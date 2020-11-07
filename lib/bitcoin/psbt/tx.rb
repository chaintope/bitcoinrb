module Bitcoin
  module PSBT

    class GlobalXpub
      include Bitcoin::HexConverter

      attr_reader :xpub # Bitcoin::ExtPubkey
      attr_reader :info # Bitcoin::PSBT::KeyOriginInfo

      def initialize(xpub, info)
        @xpub = xpub
        @info = info
      end

      def to_payload
        PSBT.serialize_to_vector(PSBT_GLOBAL_TYPES[:xpub], key: xpub.to_payload, value: info.to_payload)
      end

      def to_h
        {xpub: xpub.to_hex}.merge(info.to_h)
      end

      def to_s
        to_h.to_s
      end
    end

    class Tx
      include Bitcoin::HexConverter

      attr_accessor :tx
      attr_accessor :xpubs
      attr_reader :inputs
      attr_reader :outputs
      attr_accessor :unknowns
      attr_accessor :version_number

      def initialize(tx = nil)
        @tx = tx
        @xpubs = []
        @inputs = tx ? tx.in.map{Input.new}: []
        @outputs = tx ? tx.out.map{Output.new}: []
        @unknowns = {}
      end

      # parse Partially Signed Bitcoin Transaction data with Base64 format.
      # @param [String] base64 a Partially Signed Bitcoin Transaction data with Base64 format.
      # @return [Bitcoin::PartiallySignedTx]
      def self.parse_from_base64(base64)
        self.parse_from_payload(Base64.decode64(base64))
      end

      # parse Partially Signed Bitcoin Transaction data.
      # @param [String] payload a Partially Signed Bitcoin Transaction data with binary format.
      # @return [Bitcoin::PartiallySignedTx]
      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        raise ArgumentError, 'Invalid PSBT magic bytes.' unless buf.read(4).unpack1('N') == PSBT_MAGIC_BYTES
        raise ArgumentError, 'Invalid PSBT separator.' unless buf.read(1).bth.to_i(16) == 0xff
        partial_tx = self.new
        found_sep = false
        # read global data.
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
          when PSBT_GLOBAL_TYPES[:unsigned_tx]
            raise ArgumentError, 'Invalid global transaction typed key.' unless key_len == 1
            raise ArgumentError, 'Duplicate Key, unsigned tx already provided.' if partial_tx.tx
            partial_tx.tx = Bitcoin::Tx.parse_from_payload(value, non_witness: true)
            partial_tx.tx.in.each do |tx_in|
              raise ArgumentError, 'Unsigned tx does not have empty scriptSigs and scriptWitnesses.' if !tx_in.script_sig.empty? || !tx_in.script_witness.empty?
            end
          when PSBT_GLOBAL_TYPES[:xpub]
            raise ArgumentError, 'Size of key was not the expected size for the type global xpub.' unless key.size == Bitcoin::BIP32_EXTKEY_WITH_VERSION_SIZE
            xpub = Bitcoin::ExtPubkey.parse_from_payload(key)
            raise ArgumentError, Errors::Messages::INVALID_PUBLIC_KEY unless xpub.key.fully_valid_pubkey?
            raise ArgumentError, 'Duplicate key, global xpub already provided' if partial_tx.xpubs.any?{|x|x.xpub == xpub}
            info = Bitcoin::PSBT::KeyOriginInfo.parse_from_payload(value)
            raise ArgumentError, "global xpub's depth and the number of indexes not matched." unless xpub.depth == info.key_paths.size
            partial_tx.xpubs << Bitcoin::PSBT::GlobalXpub.new(xpub, info)
          when PSBT_GLOBAL_TYPES[:ver]
            partial_tx.version_number = value.unpack1('V')
            raise ArgumentError, "An unsupported version was detected." if SUPPORT_VERSION < partial_tx.version_number
          else
            raise ArgumentError, 'Duplicate Key, key for unknown value already provided.' if partial_tx.unknowns[key]
            partial_tx.unknowns[([key_type].pack('C') + key).bth] = value
          end
        end

        raise ArgumentError, 'Separator is missing at the end of an output map.' unless found_sep
        raise ArgumentError, 'No unsigned transaction was provided.' unless partial_tx.tx

        # read input data.
        partial_tx.tx.in.each do |tx_in|
          break if buf.eof?
          input = Input.parse_from_buf(buf)
          partial_tx.inputs << input
          if input.non_witness_utxo && input.non_witness_utxo.tx_hash != tx_in.prev_hash
            raise ArgumentError, 'Non-witness UTXO does not match outpoint hash.'
          end
        end

        raise ArgumentError, 'Inputs provided does not match the number of inputs in transaction.' unless partial_tx.inputs.size == partial_tx.tx.in.size

        # read output data.
        partial_tx.tx.outputs.each do
          break if buf.eof?
          output = Output.parse_from_buf(buf)
          break unless output
          partial_tx.outputs << output
        end

        raise ArgumentError, 'Outputs provided does not match the number of outputs in transaction.' unless partial_tx.outputs.size == partial_tx.tx.out.size

        partial_tx
      end

      # get PSBT version
      # @return [Integer] PSBT version number
      def version
        version_number ? version_number : 0
      end

      # Finds the UTXO for a given input index
      # @param [Integer] index input_index Index of the input to retrieve the UTXO of
      # @return [Bitcoin::TxOut] The UTXO of the input if found.
      def input_utxo(index)
        input = inputs[index]
        prevout_index = tx.in[index].out_point.index
        return input.non_witness_utxo.out[prevout_index] if input.non_witness_utxo
        return input.witness_utxo if input.witness_utxo
        nil
      end

      # generate payload.
      # @return [String] a payload with binary format.
      def to_payload
        payload = PSBT_MAGIC_BYTES.itb << 0xff.itb

        payload << PSBT.serialize_to_vector(PSBT_GLOBAL_TYPES[:unsigned_tx], value: tx.to_payload)
        payload << xpubs.map(&:to_payload).join
        payload << PSBT.serialize_to_vector(PSBT_GLOBAL_TYPES[:ver], value: [version_number].pack('V')) if version_number
        payload << unknowns.map {|k,v|Bitcoin.pack_var_int(k.htb.bytesize) << k.htb << Bitcoin.pack_var_int(v.bytesize) << v}.join

        payload << PSBT_SEPARATOR.itb
        payload << inputs.map(&:to_payload).join
        payload << outputs.map(&:to_payload).join
        payload
      end

      # generate payload with Base64 format.
      # @return [String] a payload with Base64 format.
      def to_base64
        Base64.strict_encode64(to_payload)
      end

      # update input key-value maps.
      # @param [Bitcoin::Tx] prev_tx previous tx reference by input.
      # @param [Bitcoin::Script] redeem_script redeem script to set input.
      # @param [Bitcoin::Script] witness_script witness script to set input.
      # @param [Hash] hd_key_paths bip 32 hd key paths to set input.
      def update!(prev_tx, redeem_script: nil, witness_script: nil, hd_key_paths: [])
        prev_hash = prev_tx.tx_hash
        tx.in.each_with_index do|tx_in, i|
          if tx_in.prev_hash == prev_hash
            utxo = prev_tx.out[tx_in.out_point.index]
            raise ArgumentError, 'redeem script does not match utxo.' if redeem_script && !utxo.script_pubkey.include?(redeem_script.to_hash160)
            raise ArgumentError, 'witness script does not match redeem script.' if redeem_script && witness_script && !redeem_script.include?(witness_script.to_sha256)
            inputs[i].witness_utxo = utxo if utxo.script_pubkey.witness_program? || redeem_script&.witness_program?
            inputs[i].non_witness_utxo = prev_tx
            inputs[i].redeem_script = redeem_script if redeem_script
            inputs[i].witness_script = witness_script if witness_script
            inputs[i].hd_key_paths = hd_key_paths.map(&:pubkey).zip(hd_key_paths).to_h
            break
          end
        end
      end

      # Check whether the signer can sign. Specifically, check the following.
      # * If a non-witness UTXO is provided, its hash must match the hash specified in the prevout
      # * If a witness UTXO is provided, no non-witness signature may be created
      # * If a redeemScript is provided, the scriptPubKey must be for that redeemScript
      # * If a witnessScript is provided, the scriptPubKey or the redeemScript must be for that witnessScript
      # @return [Boolean]
      def ready_to_sign?
        inputs.each.with_index{|psbt_in, index|return false unless psbt_in.ready_to_sign?(input_utxo(index))}
        true
      end

      # get signature script of input specified by +index+
      # @param [Integer] index input index.
      # @return [Bitcoin::Script]
      def signature_script(index)
        i = inputs[index]
        if i.non_witness_utxo
          i.redeem_script ? i.redeem_script : i.non_witness_utxo.out[tx.in[index].out_point.index].script_pubkey
        else
          i.witness_script ? i.witness_script : i.witness_utxo
        end
      end

      # merge two PSBTs to create one PSBT.
      # TODO This feature is experimental.
      # @param [Bitcoin::PartiallySignedTx] psbt PSBT to be combined which must have same property in PartiallySignedTx.
      # @return [Bitcoin::PartiallySignedTx] combined object.
      def merge(psbt)
        raise ArgumentError, 'The argument psbt must be an instance of Bitcoin::PSBT::Tx.' unless psbt.is_a?(Bitcoin::PSBT::Tx)
        raise ArgumentError, 'The combined transactions are different.' unless tx == psbt.tx
        raise ArgumentError, 'The Partially Signed Input\'s count are different.' unless inputs.size == psbt.inputs.size
        raise ArgumentError, 'The Partially Signed Output\'s count are different.' unless outputs.size == psbt.outputs.size

        combined = Bitcoin::PSBT::Tx.new(tx)
        inputs.each_with_index do |i, index|
          combined.inputs[index] = i.merge(psbt.inputs[index])
        end
        outputs.each_with_index do |o, index|
          combined.outputs[index] = o.merge(psbt.outputs[index])
        end

        combined.unknowns = Hash[unknowns.merge(psbt.unknowns).sort]
        combined
      end

      # finalize tx.
      # TODO This feature is experimental and support only multisig.
      # @return [Bitcoin::PSBT::Tx] finalized PSBT.
      def finalize!
        inputs.each {|input|input.finalize!}
        self
      end

      # extract final tx.
      # @return [Bitcoin::Tx] final tx.
      def extract_tx
        extract_tx = tx.dup
        inputs.each_with_index do |input, index|
          extract_tx.in[index].script_sig = input.final_script_sig if input.final_script_sig
          extract_tx.in[index].script_witness = input.final_script_witness if input.final_script_witness
        end
        # validate signature
        tx.in.each_with_index do |tx_in, index|
          input = inputs[index]
          if input.non_witness_utxo
            utxo = input.non_witness_utxo.out[tx_in.out_point.index]
            raise "input[#{index}]'s signature is invalid.'" unless tx.verify_input_sig(index, utxo.script_pubkey)
          else
            utxo = input.witness_utxo
            raise "input[#{index}]'s signature is invalid.'" unless tx.verify_input_sig(index, utxo.script_pubkey, amount: input.witness_utxo.value)
          end
        end
        extract_tx
      end

    end

  end
end