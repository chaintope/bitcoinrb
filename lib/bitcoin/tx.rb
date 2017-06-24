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
        tx.inputs << TxInput.parse_from_payload(buf)
      end

      out_count = Bitcoin.unpack_var_int_from_io(buf)
      out_count.times do
        tx.outputs << TxOutput.parse_from_payload(buf)
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

  end

end
