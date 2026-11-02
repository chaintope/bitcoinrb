module Bitcoin
  module Wallet
    class Utxo
      attr_reader :tx_hash
      attr_reader :index
      attr_reader :block_height
      attr_reader :value
      attr_reader :script_pubkey

      # @param [String] tx_hash The transaction hash with hex format.
      # @param [Integer] index The index of the output, 0 to 2**32 - 1.
      # @param [Integer] value The value in satoshi, 0 to 2**64 - 1.
      # @param [Bitcoin::Script] script_pubkey The scriptPubKey of the output.
      # @param [Integer, nil] block_height The height of the block which holds the tx, 1 to 2**32 - 1, or nil
      # while the tx is unconfirmed.
      # @raise [ArgumentError] If a value is out of range, since the serialization would silently change it.
      def initialize(tx_hash, index, value, script_pubkey, block_height = nil)
        unless tx_hash.is_a?(String) && tx_hash.valid_hex? && tx_hash.length == 64
          raise ArgumentError, 'tx_hash must be a 32 byte hash with hex format.'
        end
        raise ArgumentError, 'index must be an integer from 0 to 2**32 - 1.' unless index.is_a?(Integer) && index.between?(0, 0xffffffff)
        raise ArgumentError, 'value must be an integer from 0 to 2**64 - 1.' unless value.is_a?(Integer) && value.between?(0, 0xffffffffffffffff)
        raise ArgumentError, 'script_pubkey must be a Bitcoin::Script.' unless script_pubkey.is_a?(Bitcoin::Script)
        unless block_height.nil? || (block_height.is_a?(Integer) && block_height.between?(1, 0xffffffff))
          raise ArgumentError, 'block_height must be nil or an integer from 1 to 2**32 - 1.'
        end
        @tx_hash = tx_hash
        @index = index
        @block_height = block_height
        @value = value
        @script_pubkey = script_pubkey
      end

      # @param [String] payload The serialization made by #to_payload.
      # @return [Bitcoin::Wallet::Utxo, nil] nil if +payload+ is nil.
      # @raise [ArgumentError] If +payload+ is truncated or has bytes after the script.
      def self.parse_from_payload(payload)
        return nil if payload.nil?
        buf = StringIO.new(payload)
        tx_hash, index, block_height, value = Bitcoin.read_exact(buf, 48).unpack('H64VVQ<')
        script_size = Bitcoin.unpack_var_int_from_io(buf)
        script_pubkey = Bitcoin::Script.parse_from_payload(Bitcoin.read_exact(buf, script_size))
        raise ArgumentError, 'Utxo payload has data after the script.' unless buf.eof?
        new(tx_hash, index, value, script_pubkey, block_height == 0 ? nil : block_height )
      end

      def to_payload
        payload = [tx_hash, index, block_height.nil? ? 0 : block_height, value].pack('H64VVQ<')
        s = script_pubkey.to_payload
        payload << Bitcoin.pack_var_int(s.length) << s
        payload
      end
    end
  end
end