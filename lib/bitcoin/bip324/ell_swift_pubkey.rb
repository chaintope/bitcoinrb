module Bitcoin
  module BIP324
    # An ElligatorSwift-encoded public key.
    class EllSwiftPubkey
      include Schnorr::Util

      SIZE = 64

      attr_reader :key

      # Constructor
      # @param [String] key 64 bytes of key data.
      # @raise ArgumentError If key is invalid.
      def initialize(key)
        @key = hex2bin(key)
        raise ArgumentError, 'key must be 64 bytes.' unless @key.bytesize == SIZE
      end

      # Decode to public key.
      # @return [Bitcoin::Key] Decoded public key.
      def decode
        pubkey = Bitcoin.secp_impl.ellswift_decode(key)
        Bitcoin::Key.new(pubkey: pubkey, key_type: Bitcoin::Key::TYPES[:compressed])
      end

    end
  end
end
