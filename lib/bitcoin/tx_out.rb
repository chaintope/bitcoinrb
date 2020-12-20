# Porting part of the code from bitcoin-ruby. see the license.
# https://github.com/lian/bitcoin-ruby/blob/master/COPYING

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
      value = buf.read(8).unpack1('q')
      script_size = Bitcoin.unpack_var_int_from_io(buf)
      new(value: value, script_pubkey: Script.parse_from_payload(buf.read(script_size)))
    end

    def to_payload
      [value].pack('Q') << script_pubkey.to_payload(true)
    end

    def to_empty_payload
      'ffffffffffffffff00'.htb
    end

    # convert satoshi to btc
    def value_to_btc
      value / 100000000.0
    end

    def to_h
      {value: value_to_btc, script_pubkey: script_pubkey.to_h}
    end

    def ==(other)
      to_payload == other.to_payload
    end

    # Returns this output bytesize
    # @return [Integer] bytesize
    def size
      to_payload.bytesize
    end

    # Whether this output is dust or not
    # @return [Boolean]
    def dust?
      value < dust_threshold
    end

    private

    def dust_threshold
      return 0 if script_pubkey.unspendable?
      n_size = size
      n_size += script_pubkey.witness_program? ? (32 + 4 + 1 + (107 / Bitcoin::WITNESS_SCALE_FACTOR) + 4) : (32 + 4 + 1 + 107 + 4)
      fee = n_size * Bitcoin.chain_params.dust_relay_fee / 1000
      if fee == 0 && n_size != 0
        fee = Bitcoin.chain_params.dust_relay_fee > 0 ? 1 : -1
      end
      fee
    end
  end

end
