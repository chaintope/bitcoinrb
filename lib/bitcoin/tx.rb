module Bitcoin

  # Transaction class
  class Tx

    MAX_STANDARD_VERSION = 2

    # The maximum weight for transactions we're willing to relay/mine
    MAX_STANDARD_TX_WEIGHT = 400000

    MARKER = 0x00
    FLAG = 0x01

    attr_accessor :version
    attr_accessor :marker
    attr_accessor :flag
    attr_reader :inputs
    attr_reader :outputs
    attr_accessor :lock_time

    def initialize
      @inputs = []
      @outputs = []
      @version = 1
      @lock_time = 0
    end

    def self.parse_from_payload(payload)
      buf = payload.is_a?(String) ? StringIO.new(payload) : payload
      tx = new
      tx.version = buf.read(4).unpack('V').first

      in_count = Bitcoin.unpack_var_int_from_io(buf)
      witness = false
      if in_count.zero?
        tx.marker = 0
        tx.flag = buf.read(1).unpack('c').first
        if tx.flag.zero?
          buf.pos -= 1
        else
          in_count = Bitcoin.unpack_var_int_from_io(buf)
          witness = true
        end
      end

      in_count.times do
        tx.inputs << TxIn.parse_from_payload(buf)
      end

      out_count = Bitcoin.unpack_var_int_from_io(buf)
      out_count.times do
        tx.outputs << TxOut.parse_from_payload(buf)
      end

      if witness
        in_count.times do |i|
          witness_count = Bitcoin.unpack_var_int_from_io(buf)
          witness_count.times do
            size = Bitcoin.unpack_var_int_from_io(buf)
            tx.inputs[i].script_witness.stack << buf.read(size)
          end
        end
      end

      tx.lock_time = buf.read(4).unpack('V').first

      tx
    end

    def txid
      Bitcoin.double_sha256(serialize_old_format).reverse.bth
    end

    def wtxid
      Bitcoin.double_sha256(to_payload).reverse.bth
    end

    # get the witness commitment of coinbase tx.
    # if this tx does not coinbase or not have commitment, return nil.
    def witness_commitment
      return nil unless coinbase_tx?
      outputs.each do |output|
        commitment = output.script_pubkey.witness_commitment
        return commitment if commitment
      end
      nil
    end

    def to_payload
      witness? ? serialize_witness_format : serialize_old_format
    end

    def coinbase_tx?
      inputs.length == 1 && inputs.first.coinbase?
    end

    def witness?
      !inputs.find { |i| !i.script_witness.empty? }.nil?
    end

    # serialize tx with old tx format
    def serialize_old_format
      buf = [version].pack('V')
      buf << Bitcoin.pack_var_int(inputs.length) << inputs.map(&:to_payload).join
      buf << Bitcoin.pack_var_int(outputs.length) << outputs.map(&:to_payload).join
      buf << [lock_time].pack('V')
      buf
    end

    # serialize tx with segwit tx format
    # https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki
    def serialize_witness_format
      buf = [version, MARKER, FLAG].pack('Vcc')
      buf << Bitcoin.pack_var_int(inputs.length) << inputs.map(&:to_payload).join
      buf << Bitcoin.pack_var_int(outputs.length) << outputs.map(&:to_payload).join
      buf << witness_payload << [lock_time].pack('V')
      buf
    end

    def witness_payload
      inputs.map { |i| i.script_witness.to_payload }.join
    end

    # check this tx is standard.
    def standard?
      return false if version > MAX_STANDARD_VERSION
      return false if weight > MAX_STANDARD_TX_WEIGHT
      inputs.each do |i|
        # Biggest 'standard' txin is a 15-of-15 P2SH multisig with compressed keys (remember the 520 byte limit on redeemScript size).
        # That works out to a (15*(33+1))+3=513 byte redeemScript, 513+1+15*(73+1)+3=1627
        # bytes of scriptSig, which we round off to 1650 bytes for some minor future-proofing.
        # That's also enough to spend a 20-of-20 CHECKMULTISIG scriptPubKey, though such a scriptPubKey is not considered standard.
        return false if i.script_sig.size > 1650
        return false unless i.script_sig.push_only?
      end
      data_count = 0
      outputs.each do |o|
        return false unless o.script_pubkey.standard?
        data_count += 1 if o.script_pubkey.op_return?
        # TODO add non P2SH multisig relay(permitbaremultisig)
        # TODO add dust relay check
      end
      return false if data_count > 1
      true
    end

    # The serialized transaction size
    def size
      to_payload.bytesize
    end

    # The virtual transaction size (differs from size for witness transactions)
    def vsize
      (weight.to_f / 4).ceil
    end

    # calculate tx weight
    # weight = (legacy tx payload) * 3 + (witness tx payload)
    def weight
      if witness?
        serialize_old_format.bytesize * (WITNESS_SCALE_FACTOR - 1) + serialize_witness_format.bytesize
      else
        serialize_old_format.bytesize * WITNESS_SCALE_FACTOR
      end
    end

    # get signature hash
    # @param [Integer] input_index input index.
    # @param [Integer] hash_type signature hash type
    # @param [Bitcoin::Script] output_script script pubkey or script code. if script pubkey is P2WSH, set witness script to this.
    # @param [Integer] amount bitcoin amount locked in input. required for witness input only.
    # @param [Integer] skip_separator_index If output_script is P2WSH and output_script contains any OP_CODESEPARATOR,
    # the script code needs  is the witnessScript but removing everything up to and including the last executed OP_CODESEPARATOR before the signature checking opcode being executed.
    def sighash_for_input(input_index, output_script, hash_type: SIGHASH_TYPE[:all],
                          sig_version: :base, amount: nil, skip_separator_index: 0)
      raise ArgumentError, 'input_index must be specified.' unless input_index
      raise ArgumentError, 'does not exist input corresponding to input_index.' if input_index >= inputs.size
      raise ArgumentError, 'script_pubkey must be specified.' unless output_script
      raise ArgumentError, 'unsupported sig version specified.' unless SIG_VERSION.include?(sig_version)

      if sig_version == :witness_v0
        raise ArgumentError, 'amount must be specified.' unless amount
        sighash_for_witness(input_index, output_script, hash_type, amount, skip_separator_index)
      else
        sighash_for_legacy(input_index, output_script, hash_type)
      end
    end

    # verify input signature.
    # @param [Integer] input_index
    # @param [Bitcoin::Script] script_pubkey the script pubkey for target input.
    # @param [Integer] amount the amount of bitcoin, require for witness program only.
    # @param [Array] flags the flags used when execute script interpreter.
    def verify_input_sig(input_index, script_pubkey, amount: nil, flags: STANDARD_SCRIPT_VERIFY_FLAGS)
      script_sig = inputs[input_index].script_sig
      has_witness = inputs[input_index].has_witness?

      if script_pubkey.p2sh?
        flags << SCRIPT_VERIFY_P2SH
        redeem_script = Script.parse_from_payload(script_sig.chunks.last)
        script_pubkey = redeem_script if redeem_script.p2wpkh?
      end

      if has_witness
        verify_input_sig_for_witness(input_index, script_pubkey, amount, flags)
      else
        verify_input_sig_for_legacy(input_index, script_pubkey, flags)
      end
    end

    private

    # generate sighash with legacy format
    def sighash_for_legacy(index, script_code, hash_type)
      ins = inputs.map.with_index do |i, idx|
        if idx == index
          i.to_payload(script_code.delete_opcode(Bitcoin::Opcodes::OP_CODESEPARATOR))
        else
          case hash_type & 0x1f
            when SIGHASH_TYPE[:none], SIGHASH_TYPE[:single]
              i.to_payload(Bitcoin::Script.new, 0)
            else
              i.to_payload(Bitcoin::Script.new)
          end
        end
      end

      outs = outputs.map(&:to_payload)
      out_size = Bitcoin.pack_var_int(outputs.size)

      case hash_type & 0x1f
        when SIGHASH_TYPE[:none]
          outs = ''
          out_size = Bitcoin.pack_var_int(0)
        when SIGHASH_TYPE[:single]
          return "\x01".ljust(32, "\x00") if index >= outputs.size
          outs = outputs[0...(index + 1)].map.with_index { |o, idx| (idx == index) ? o.to_payload : o.to_empty_payload }.join
          out_size = Bitcoin.pack_var_int(index + 1)
      end

      if hash_type & SIGHASH_TYPE[:anyonecanpay] != 0
        ins = [ins[index]]
      end

      buf = [[version].pack('V'), Bitcoin.pack_var_int(ins.size),
          ins, out_size, outs, [lock_time, hash_type].pack('VV')].join

      Bitcoin.double_sha256(buf)
    end

    # generate sighash with BIP-143 format
    # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    def sighash_for_witness(index, script_pubkey_or_script_code, hash_type, amount, skip_separator_index)
      hash_prevouts = Bitcoin.double_sha256(inputs.map{|i|i.out_point.to_payload}.join)
      hash_sequence = Bitcoin.double_sha256(inputs.map{|i|[i.sequence].pack('V')}.join)
      outpoint = inputs[index].out_point.to_payload
      amount = [amount].pack('Q')
      nsequence = [inputs[index].sequence].pack('V')
      hash_outputs = Bitcoin.double_sha256(outputs.map{|o|o.to_payload}.join)

      script_code = script_pubkey_or_script_code.to_script_code(skip_separator_index)

      case (hash_type & 0x1f)
      when SIGHASH_TYPE[:single]
        hash_outputs = index >= outputs.size ? "\x00".ljust(32, "\x00") : Bitcoin.double_sha256(outputs[index].to_payload)
        hash_sequence = "\x00".ljust(32, "\x00")
      when SIGHASH_TYPE[:none]
        hash_sequence = hash_outputs = "\x00".ljust(32, "\x00")
      end

      if (hash_type & SIGHASH_TYPE[:anyonecanpay]) != 0
        hash_prevouts = hash_sequence ="\x00".ljust(32, "\x00")
      end
      buf = [ [version].pack('V'), hash_prevouts, hash_sequence, outpoint,
              script_code ,amount, nsequence, hash_outputs, [@lock_time, hash_type].pack('VV')].join
      Bitcoin.double_sha256(buf)
    end

    # verify input signature for legacy tx.
    def verify_input_sig_for_legacy(input_index, script_pubkey, flags)
      script_sig = inputs[input_index].script_sig
      checker = Bitcoin::TxChecker.new(tx: self, input_index: input_index)
      interpreter = Bitcoin::ScriptInterpreter.new(checker: checker, flags: flags)

      interpreter.verify_script(script_sig, script_pubkey)
    end

    # verify input signature for witness tx.
    def verify_input_sig_for_witness(input_index, script_pubkey, amount, flags)
      flags << SCRIPT_VERIFY_WITNESS
      flags << SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
      checker = Bitcoin::TxChecker.new(tx: self, input_index: input_index, amount: amount)
      interpreter = Bitcoin::ScriptInterpreter.new(checker: checker, flags: flags)
      i = inputs[input_index]

      script_sig = i.script_sig
      witness = i.script_witness
      interpreter.verify_script(script_sig, script_pubkey, witness)
    end

  end

end
