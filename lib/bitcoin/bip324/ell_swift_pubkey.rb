module Bitcoin
  module BIP324
    # An ElligatorSwift-encoded public key.
    class EllSwiftPubkey
      include Schnorr::Util

      SIZE = 64

      attr_reader :key

      # Constructor
      # @param [String] key 64 bytes of key data.
      # @raise Bitcoin::BIP324::InvalidEllSwiftKey If key is invalid.
      def initialize(key)
        @key = hex2bin(key)
        raise Bitcoin::BIP324::InvalidEllSwiftKey, 'key must be 64 bytes.' unless @key.bytesize == SIZE
      end

      # Decode to public key.
      # @return [Bitcoin::Key] Decoded public key.
      def decode
        if Bitcoin.secp_impl.native?
          pubkey = Bitcoin.secp_impl.ellswift_decode(key)
          Bitcoin::Key.new(pubkey: pubkey, key_type: Bitcoin::Key::TYPES[:compressed])
        else
          u = key[0...32].bth
          t = key[32..-1].bth
          x = BIP324.xswiftec(u, t)
          Bitcoin::Key.new(pubkey: "03#{x}")
        end
      end

      # Check whether same public key or not?
      # @param [Bitcoin::BIP324::EllSwiftPubkey] other
      # @return [Boolean]
      def ==(other)
        return false unless other.is_a?(EllSwiftPubkey)
        key == other.key
      end
    end
  end
end
