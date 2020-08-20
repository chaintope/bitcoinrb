module Bitcoin
  module PSBT

    # HD Key path data structure.
    # see https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#Specification
    class HDKeyPath

      attr_reader :pubkey # String
      attr_reader :info   # KeyOriginInfo

      def initialize(pubkey, info)
        pubkey = pubkey.encoding == Encoding::ASCII_8BIT ? pubkey : pubkey.htb
        raise ArgumentError, 'Size of key was not the expected size for the type BIP32 keypath.' unless [Bitcoin::Key::PUBLIC_KEY_SIZE, Bitcoin::Key::COMPRESSED_PUBLIC_KEY_SIZE].include?(pubkey.bytesize)
        pubkey = Bitcoin::Key.new(pubkey: pubkey.bth)
        raise ArgumentError, Errors::Messages::INVALID_PUBLIC_KEY unless pubkey.fully_valid_pubkey?
        @pubkey = pubkey.pubkey
        @info = info
      end

      # generate payload which consist of pubkey and fingerprint, hd key path payload.
      # @return [String] a payload
      def to_payload(type = PSBT_IN_TYPES[:bip32_derivation])
        PSBT.serialize_to_vector(type, key: pubkey.htb, value: info.to_payload)
      end

      def to_h
        {pubkey: pubkey}.merge(info.to_h)
      end

      def to_s
        to_h.to_s
      end

    end
  end
end