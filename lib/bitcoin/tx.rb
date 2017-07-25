module Bitcoin

  # Transaction class
  class Tx

    MARKER = 0
    FLAG = 1

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
        in_count = Bitcoin.unpack_var_int_from_io(buf)
        witness = true
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
            tx.inputs[i].script_witness.stack << buf.read(size).bth
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

    # get signature hash
    # @param [Integer] input_index input index.
    # @param [Integer] hash_type signature hash type
    # @param [Bitcoin::Script] script_pubkey locked script
    # @param [Integer] amount bitcoin amount locked in input. required for witness input only.
    def sighash_for_input(input_index: nil, hash_type: Script::SIGHASH_TYPE[:all], script_pubkey: nil, amount: nil)
      raise ArgumentError, 'input_index must be specified.' unless input_index
      raise ArgumentError, 'does not exist input corresponding to input_index.' if input_index >= inputs.size
      raise ArgumentError, 'script_pubkey must be specified.' unless script_pubkey

      if script_pubkey.witness_program?
        raise ArgumentError, 'amount must be specified.' unless amount
      else
        sighash_for_legacy(input_index, script_pubkey, hash_type)
      end
    end

    private

    # generate sighash with legacy format
    def sighash_for_legacy(index, script_pubkey, hash_type)
      ins = inputs.map.with_index do |i, idx|
        if idx == index
          i.to_payload(script_pubkey)
        else
          case hash_type & 0x1f
            when Script::SIGHASH_TYPE[:none], Script::SIGHASH_TYPE[:single]
              i.to_payload(Bitcoin::Script.new, 0)
            else
              i.to_payload(Bitcoin::Script.new)
          end
        end
      end

      outs = outputs.map(&:to_payload)
      out_size = Bitcoin.pack_var_int(outputs.size)

      case hash_type & 0x1f
        when Script::SIGHASH_TYPE[:none]
          outs = ''
          out_size = Bitcoin.pack_var_int(0)
        when Script::SIGHASH_TYPE[:single]
          return "\x01".ljust(32, "\x00") if index >= outputs.size
          outs = outputs[0...(index + 1)].map.with_index { |o, idx| (idx == index) ? o.to_payload : o.to_empty_payload }.join
          out_size = Bitcoin.pack_var_int(index + 1)
      end

      if hash_type & Script::SIGHASH_TYPE[:anyonecanpay] != 0
        ins = [ins[index]]
      end

      buf = [[version].pack('V'), Bitcoin.pack_var_int(ins.size),
          ins, out_size, outs, [lock_time, hash_type].pack('VV')].join

      Bitcoin.double_sha256(buf)
    end

    # generate sighash with BIP-143 format
    # https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    def sighash_for_witness
      # TODO
    end

  end

end
