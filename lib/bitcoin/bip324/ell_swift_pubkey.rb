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
        if Bitcoin.secp_impl.is_a?(Bitcoin::Secp256k1::Native)
          pubkey = Bitcoin.secp_impl.ellswift_decode(key)
          Bitcoin::Key.new(pubkey: pubkey, key_type: Bitcoin::Key::TYPES[:compressed])
        else
          u = key[0...32].bth
          t = key[32..-1].bth
          x = BIP324.xswiftec(u, t)
          Bitcoin::Key.new(pubkey: "03#{x}")
        end
      end

    end
  end
end
