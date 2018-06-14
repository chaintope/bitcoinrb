module Bitcoin

  # constants for PSBT
  PSBT_MAGIC_BYTES = 0x70736274
  PSBT_TYPES = {tx_or_non_witness: 0x00, redeem_or_witness_utxo: 0x01,
                witness_or_partial_sig: 0x02, key_path_or_sighash: 0x03, input_num_or_index: 0x04}
  PSBT_SEPARATOR = 0x00

  # Partially Signed Bitcoin Transaction
  class PartiallySignedTx

    attr_accessor :tx
    attr_accessor :redeem_scripts
    attr_accessor :witness_scripts
    attr_accessor :partial_inputs
    attr_accessor :hd_key_paths
    attr_accessor :num_input
    attr_accessor :unknowns
    attr_accessor :use_in_index

    def initialize(tx = nil)
      @tx = tx
      @redeem_scripts = {}
      @witness_scripts = {}
      @partial_inputs = []
      @hd_key_paths = {}
      @unknowns = {}
      @use_in_index = false
    end

    # parse Partially Signed Bitcoin Transaction data.
    # @param [String] payload a Partially Signed Bitcoin Transaction data with binary format.
    # @return [Bitcoin::PartiallySignedTx]
    def self.parse_from_payload(payload)
      buf = StringIO.new(payload)
      raise ArgumentError, 'Invalid PSBT magic bytes.' unless buf.read(4).unpack('N').first == PSBT_MAGIC_BYTES
      raise ArgumentError, 'Invalid PSBT separator.' unless buf.read(1).bth.to_i(16) == 0xff
      partial_tx = self.new
      is_global = true
      separators = 0
      input = PartiallySignedInput.new
      until buf.eof?
        key_len = Bitcoin.unpack_var_int_from_io(buf)
        if key_len == 0
          puts "use child"
          is_global = false
          if separators > 0
            if partial_tx.use_in_index
              raise ArgumentError, 'Input indexes being used but an input was provided without an index' unless input.use_in_index
              (partial_tx.partial_inputs.size...input.index).each{partial_tx.partial_inputs << PartiallySignedInput.new}
            end
            partial_tx.partial_inputs << input
            input = PartiallySignedInput.new(separators)
          end
          separators += 1
          next
        end

        key_type = buf.read(1).unpack('C').first
        key = buf.read(key_len - 1)
        value = buf.read(Bitcoin.unpack_var_int_from_io(buf))
        puts "key_len = #{key_len}[#{key_type}] key: #{key.nil? ? key : key.bth}, value: #{value.bth}"

        raise ArgumentError, 'Missing null terminator.' if buf.eof? && (key_type != 0 || !key.empty? || !value.empty?)

        case key_type
        when PSBT_TYPES[:tx_or_non_witness]
          tx = Bitcoin::Tx.parse_from_payload(value)
          if is_global
            partial_tx.tx = tx
          else
            raise ArgumentError, 'Provided non witness utxo does not match the required utxo for input' unless partial_tx.tx.in[input.index].out_point.hash == tx.hash
            input.non_witness_utxo = tx
          end
        when PSBT_TYPES[:redeem_or_witness_utxo]
          if is_global
            redeem_hash = key
            raise ArgumentError, 'Size of key was not the expected size for the type redeem script' unless redeem_hash.bytesize == 20
            raise ArgumentError, 'Provided hash160 does not match the redeemscript\'s hash160' unless Bitcoin.hash160(value.bth) == redeem_hash.bth
            partial_tx.redeem_scripts[redeem_hash.bth] = value
          else
            input.witness_utxo = Bitcoin::TxOut.parse_from_payload(value)
          end
        when PSBT_TYPES[:witness_or_partial_sig]
          if is_global
            witness_hash = key
            raise ArgumentError, 'Size of key was not the expected size for the type witness script' unless witness_hash.bytesize == 32
            raise ArgumentError, 'Provided sha256 does not match the witnessscript\'s sha256' unless Bitcoin.sha256(value) == witness_hash
            partial_tx.witness_scripts[witness_hash.bth] = value
          else
            raise ArgumentError, 'Size of key was not the expected size for the type partial signature pubkey' unless [33, 65].include?(key.bytesize)
            pubkey = Bitcoin::Key.new(pubkey: key.bth)
            raise ArgumentError, 'Invalid pubkey' unless pubkey.fully_valid_pubkey?
            input.partial_sigs[pubkey.pubkey] = value
          end
        when PSBT_TYPES[:key_path_or_sighash]
          if is_global
            raise ArgumentError, 'Size of key was not the expected size for the type BIP32 keypath' unless [33, 65].include?(key.bytesize)
            pubkey = Bitcoin::Key.new(pubkey: key.bth)
            raise ArgumentError, 'Invalid pubkey' unless pubkey.fully_valid_pubkey?
            key_paths = []
            key_paths << value[0...4] # fingerprint
            key_paths += value[4..-1].unpack('N*')
            partial_tx.hd_key_paths[pubkey.pubkey] = key_paths
          else
            input.sighash_type = value.unpack('N').first
          end
        when PSBT_TYPES[:input_num_or_index]
          if is_global
            partial_tx.num_input = Bitcoin.unpack_var_int(value).first
          else
            input.index = Bitcoin.unpack_var_int(value).first
            input.use_in_index = true
            partial_tx.use_in_index = true
          end
        else
          if is_global
            partial_tx.unknowns[([key_type].pack('C') + key).bth] = value
          else
            input.unknowns[([key_type].pack('C') + key).bth] = value
          end
        end
      end
      raise ArgumentError, 'Inputs provided does not match the number of inputs stated.' if (separators - 1) != partial_tx.num_input && partial_tx.use_in_index
      raise ArgumentError, 'Inputs provided does not match the number of inputs in transaction.' unless partial_tx.tx.in.size == partial_tx.partial_inputs.size
      partial_tx
    end

    # generate payload.
    # @return [String] a payload with binary format.
    def to_payload
      payload = PSBT_MAGIC_BYTES.to_even_length_hex.htb << 0xff.to_even_length_hex.htb
      payload << serialize_to_vector(PSBT_TYPES[:tx_or_non_witness], value: tx.to_payload) if tx

      redeem_scripts.each do |k, v|
        payload << serialize_to_vector(PSBT_TYPES[:redeem_or_witness_utxo], key: k.htb, value: v)
      end

      witness_scripts.each do |k, v|
        payload << serialize_to_vector(PSBT_TYPES[:witness_or_partial_sig], key: k.htb, value: v)
      end

      hd_key_paths.each do |k, v|
        value = v.map.with_index{|v, i| i == 0 ? v : [v].pack('N')}.join
        payload << serialize_to_vector(PSBT_TYPES[:key_path_or_sighash], key: k.htb, value: value)
      end

      payload << serialize_to_vector(PSBT_TYPES[:input_num_or_index], value: Bitcoin.pack_var_int(num_input)) if num_input

      unknowns.each do |k,v|
        puts "key = #{k}, v = #{v.bth}"
        payload << Bitcoin.pack_var_int(k.htb.bytesize) << k.htb << Bitcoin.pack_var_int(v.bytesize) << v
      end

      payload << PSBT_SEPARATOR.to_even_length_hex.htb

      tx.inputs.each_with_index do|tx_in, index|
        partial_input = partial_inputs[index]
        next if use_in_index && !partial_input.use_in_index
        if tx_in.script_sig.empty? && tx_in.script_witness.empty?
          if partial_input.non_witness_utxo
            payload << serialize_to_vector(PSBT_TYPES[:tx_or_non_witness], value: partial_input.non_witness_utxo.to_payload)
          elsif partial_input.witness_utxo
            payload << serialize_to_vector(PSBT_TYPES[:redeem_or_witness_utxo], value: partial_input.witness_utxo.to_payload)
          end
          partial_input.partial_sigs.each do |k, v|
            payload << serialize_to_vector(PSBT_TYPES[:witness_or_partial_sig], key: k.htb, value: v)
          end
          payload << serialize_to_vector(PSBT_TYPES[:key_path_or_sighash], value: [partial_input.sighash_type].pack('N')) if partial_input.sighash_type
          payload << serialize_to_vector(PSBT_TYPES[:input_num_or_index], value: Bitcoin.pack_var_int(partial_input.index)) if partial_input.use_in_index
          partial_input.unknowns.each do |k,v|
            payload << Bitcoin.pack_var_int(k.htb.bytesize) << k.htb << Bitcoin.pack_var_int(v.bytesize) << v
          end
        end
        payload << PSBT_SEPARATOR.to_even_length_hex.htb
      end

      payload
    end

    # combine two PSBTs to create one PSBT.
    # TODO This feature is experimental.
    # @param [Bitcoin::PartiallySignedTx] psbt PSBT to be combined which must have same property in PartiallySignedTx.
    # @return [Bitcoin::PartiallySignedTx] combined object.
    def combine(psbt)
      raise ArgumentError, 'The argument psbt must be an instance of PartiallySignedTx.' unless psbt.is_a?(PartiallySignedTx)
      raise ArgumentError, 'The combined transactions are different.' unless tx == psbt.tx
      raise ArgumentError, 'The use_in_index are different.' unless use_in_index == psbt.use_in_index
      raise ArgumentError, 'The partial_inputs size are different.' unless partial_inputs.size == psbt.partial_inputs.size
      raise ArgumentError, 'The unknowns are different.' unless unknowns == psbt.unknowns
      combined = PartiallySignedTx.new(tx)
      combined.redeem_scripts = redeem_scripts.merge(psbt.redeem_scripts)
      combined.witness_scripts = witness_scripts.merge(psbt.witness_scripts)
      combined.hd_key_paths = hd_key_paths.merge(psbt.hd_key_paths)
      combined.witness_scripts = witness_scripts.merge(psbt.witness_scripts)
      partial_inputs.each_with_index {|i, index|combined.partial_inputs[index] = i.combine(psbt.partial_inputs[index])}
      combined
    end

    # transforms a PSBT into a network serialized transaction.
    # For any inputs which are not complete, the Finalizer will emplace an empty scriptSig in the network serialized transaction.
    # For any input which has a complete set of signatures,
    # the Finalizer must attempt to build the complete scriptSig and encode it into the network serialized transaction.
    # TODO This feature is experimental and support only multisig.
    # @return [Bitcoin::Tx] finalized Tx.
    def finalize
      finalize_tx = tx.dup
      finalize_tx.inputs.each_with_index do |tx_in, i|
        partial_input = partial_inputs[i]
        if partial_input.non_witness_utxo
          utxo = partial_input.non_witness_utxo.out[tx_in.out_point.index]
          redeem_script = Bitcoin::Script.parse_from_payload(redeem_scripts[utxo.script_pubkey.chunks[1].pushed_data.bth])
          tx_in.script_sig << Bitcoin::Opcodes::OP_0
          redeem_script.chunks[1..-3].each do |pubkey|
            tx_in.script_sig << partial_input.partial_sigs[pubkey.pushed_data.bth].bth
          end
          tx_in.script_sig << redeem_script.to_payload.bth
          # tx_in.script_sig = Bitcoin::Script.new unless finalize_tx.verify_input_sig(i, utxo.script_pubkey)
        elsif partial_input.witness_utxo
          utxo = partial_input.witness_utxo
          tx_in.script_witness.stack << ''
          witness_scripts.each {|k, v|
            redeem_script = Bitcoin::Script.parse_from_payload(v)
            p2wsh = Bitcoin::Script.to_p2wsh(redeem_script)
            if p2wsh.to_p2sh == utxo.script_pubkey
              redeem_script.chunks[1..-3].each do |pubkey|
                tx_in.script_witness.stack << partial_input.partial_sigs[pubkey.pushed_data.bth]
              end
              tx_in.script_witness.stack << v
              tx_in.script_sig << p2wsh.to_payload.bth
              break
            end
          }
          unless finalize_tx.verify_input_sig(i, utxo.script_pubkey, amount: utxo.value)
            tx_in.script_sig = Bitcoin::Script.new
            tx_in.script_witness = Bitcoin::ScriptWitness.new
          end
        end
      end
      finalize_tx
    end

    private

    def serialize_to_vector(key_type, key: nil, value: nil)
      key_len = key_type.to_even_length_hex.htb.bytesize
      key_len += key.bytesize if key
      s = Bitcoin.pack_var_int(key_len) << Bitcoin.pack_var_int(key_type)
      s << key if key
      s << Bitcoin.pack_var_int(value.bytesize) << value
      s
    end

  end

  class PartiallySignedInput

    attr_accessor :non_witness_utxo # Bitcoin::Tx
    attr_accessor :witness_utxo # Bitcoin::TxOut
    attr_accessor :partial_sigs
    attr_accessor :sighash_type
    attr_accessor :index
    attr_accessor :unknowns
    attr_accessor :use_in_index

    def initialize(index = 0, non_witness_utxo: nil, witness_utxo: nil)
      @non_witness_utxo = non_witness_utxo
      @witness_utxo = witness_utxo
      @partial_sigs = {}
      @index = index
      @unknowns = {}
      @use_in_index = false
    end

    # combine two PSBTs to create one PSBT.
    # @param [Bitcoin::PartiallySignedInput] psbi PSBI to be combined which must have same property in PartiallySignedInput.
    # @return [Bitcoin::PartiallySignedInput] combined object.
    def combine(psbi)
      raise ArgumentError, 'The argument psbt must be an instance of PartiallySignedInput.' unless psbi.is_a?(PartiallySignedInput)
      raise ArgumentError, 'The Partially Signed Input\'s non_witness_utxo are different.' unless non_witness_utxo == psbi.non_witness_utxo
      raise ArgumentError, 'The Partially Signed Input\'s witness_utxo are different.' unless witness_utxo == psbi.witness_utxo
      raise ArgumentError, 'The Partially Signed Input\'s sighash_type are different.' unless sighash_type == psbi.sighash_type
      raise ArgumentError, 'The Partially Signed Input\'s use_in_index are different.' unless use_in_index == psbi.use_in_index
      combined = PartiallySignedInput.new(index, non_witness_utxo: non_witness_utxo, witness_utxo: witness_utxo)
      combined.use_in_index = use_in_index
      combined.unknowns = unknowns.merge(psbi.unknowns)
      combined.partial_sigs = Hash[partial_sigs.merge(psbi.partial_sigs).sort]
      combined
    end

  end

end
