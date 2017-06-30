module Bitcoin

  # transaction input
  class TxIn

    attr_accessor :out_point
    attr_accessor :script_sig
    attr_accessor :sequence
    attr_accessor :script_witness

    def initialize
      @script_witness = ScriptWitness.new
    end

    def self.parse_from_payload(payload)
      buf = payload.is_a?(String) ? StringIO.new(payload) : payload
      i = new
      hash, index = buf.read(36).unpack('a32V')
      i.out_point = OutPoint.new(hash.reverse.bth, index)
      sig_length = Bitcoin.unpack_var_int_from_io(buf)
      i.script_sig = Script.new(buf.read(sig_length))
      i.sequence = buf.read(4).unpack('V').first
      i
    end

    def coinbase?
      out_point.coinbase?
    end

    def to_payload
      p = out_point.to_payload
      p << Bitcoin.pack_var_int(script_sig.payload.bytesize)
      p << script_sig.payload << [sequence].pack('V')
    end

  end

end
