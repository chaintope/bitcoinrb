module Bitcoin

  # transaction output
  class TxOut

    attr_accessor :value
    attr_accessor :script_pubkey

    def initialize(value, script_pubkey)
      @value = value
      @script_pubkey = script_pubkey
    end

    def self.parse_from_payload(payload)
      buf = payload.is_a?(String) ? StringIO.new(payload) : payload
      value = buf.read(8).unpack('Q').first
      script_size = Bitcoin.unpack_var_int_from_io(buf)
      new(value, Script.new(buf.read(script_size)))
    end

    def to_payload
      s = script_pubkey.payload
      [value].pack('Q') << Bitcoin.pack_var_int(s.length) << s
    end

  end

end
