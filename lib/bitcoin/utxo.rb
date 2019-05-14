module Bitcoin
  class Utxo
    attr_reader :tx_hash
    attr_reader :index
    attr_reader :block_height
    attr_reader :value
    attr_reader :script_pubkey

    def initialize(tx_hash, index, value, script_pubkey, block_height = nil)
      @tx_hash = tx_hash
      @index = index
      @block_height = block_height
      @value = value
      @script_pubkey = script_pubkey
    end

    # def to_payload()
    #   buf = [hash, index, block_height, value, script_pubkey].pack('V')
    #   # buf << Bitcoin.pack_var_int(inputs.length) << inputs.map(&:to_payload).join
    #   # buf << Bitcoin.pack_var_int(outputs.length) << outputs.map(&:to_payload).join
    #   # buf << [lock_time].pack('V')
    #   buf
    # end

    # def parse_from_payload(payload)
    #   nil
    # end

    def self.parse_from_payload(payload)
      return nil if payload.nil?

      buf = StringIO.new(payload)
      tx_hash, payload = Bitcoin.unpack_var_string(payload)
      tx_hash = tx_hash.force_encoding('utf-8')
      script_pubkey, payload = Bitcoin.unpack_var_string(payload)
      script_pubkey = script_pubkey.force_encoding('utf-8')
      script_pubkey = Bitcoin::Script.parse_from_payload(script_pubkey);
      index, value, block_height = payload.unpack('I*')
      a = new(tx_hash, index, value, script_pubkey, block_height == 0 ? nil : block_height )
      a
    end

    def to_payload
      payload = Bitcoin.pack_var_string(tx_hash.unpack('H*').first.htb)
      payload << Bitcoin.pack_var_string(script_pubkey.to_payload.unpack('H*').first.htb)
      payload << [index, value, block_height.nil? ? 0 : block_height].pack('I*')
      payload
    end
  end
end