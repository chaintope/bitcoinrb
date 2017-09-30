module Bitcoin

  # transaction output
  class TxOut

    include OpenAssets::MarkerOutput

    attr_accessor :value
    attr_accessor :script_pubkey

    def initialize(value: 0, script_pubkey: nil)
      @value = value
      @script_pubkey = script_pubkey
    end

    def self.parse_from_payload(payload)
      buf = payload.is_a?(String) ? StringIO.new(payload) : payload
      value = buf.read(8).unpack('q').first
      script_size = Bitcoin.unpack_var_int_from_io(buf)
      new(value: value, script_pubkey: Script.parse_from_payload(buf.read(script_size)))
    end

    def to_payload
      s = script_pubkey.to_payload
      [value].pack('Q') << Bitcoin.pack_var_int(s.length) << s
    end

    def to_empty_payload
      'ffffffffffffffff00'.htb
    end

  end

end
