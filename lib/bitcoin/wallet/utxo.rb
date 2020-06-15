module Bitcoin
  module Wallet
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

      def self.parse_from_payload(payload)
        return nil if payload.nil?

        tx_hash, index, block_height, value, payload = payload.unpack('H64VVQa*')

        buf = StringIO.new(payload)
        script_size = Bitcoin.unpack_var_int_from_io(buf)
        script_pubkey = Bitcoin::Script.parse_from_payload(buf.read(script_size));
        new(tx_hash, index, value, script_pubkey, block_height == 0 ? nil : block_height )
      end

      def to_payload
        payload = [tx_hash, index, block_height.nil? ? 0 : block_height, value].pack('H64VVQ')
        s = script_pubkey.to_payload
        payload << Bitcoin.pack_var_int(s.length) << s
        payload
      end
    end
  end
end