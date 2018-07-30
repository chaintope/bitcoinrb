module Bitcoin
  module PSBT

    # HD Key path data structure.
    # see https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#Specification
    class HDKeyPath

      attr_reader :pubkey
      attr_accessor :fingerprint
      attr_reader :path

      def initialize(pubkey, fingerprint: nil, path: [])
        @pubkey = pubkey
        @fingerprint = fingerprint
        @path = path
      end

      # parse hd key path from payload.
      # @param [String] pubkey a public key with binary format.
      # @param [String] payload hd key path value with binary format.
      # @return [Bitcoin::PSBT::HDKeyPath]
      def self.parse_from_payload(pubkey, payload)
        raise 'Size of key was not the expected size for the type BIP32 keypath' unless [Bitcoin::Key::PUBLIC_KEY_SIZE, Bitcoin::Key::COMPRESSED_PUBLIC_KEY_SIZE].include?(pubkey.bytesize)
        pubkey = Bitcoin::Key.new(pubkey: pubkey.bth)
        raise 'Invalid pubkey' unless pubkey.fully_valid_pubkey?
        self.new(pubkey.pubkey, fingerprint: payload[0...4].bth, path: payload[4..-1].unpack('I*'))
      end

      # generate payload which consist of pubkey and fingerprint, hd key path payload.
      # @return [String] a payload
      def to_payload(type = PSBT_IN_TYPES[:bip32_derivation])
        PSBT.serialize_to_vector(type, key: pubkey.htb, value: fingerprint.htb + path.pack('I*'))
      end

    end
  end
end