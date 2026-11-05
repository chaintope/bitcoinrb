module Bitcoin
  module Message
    # inventory class. inventory is a part of message.
    # https://bitcoin.org/en/developer-reference#term-inventory
    class Inventory

      SEGWIT_FLAG = 1 << 30

      MSG_TX = 1
      MSG_BLOCK = 2
      MSG_FILTERED_BLOCK = 3
      MSG_CMPCT_BLOCK = 4
      MSG_WTX = 5 # BIP-339, the hash is a wtxid.
      MSG_WITNESS_TX = SEGWIT_FLAG | MSG_TX
      MSG_WITNESS_BLOCK = SEGWIT_FLAG | MSG_BLOCK
      MSG_FILTERED_WITNESS_BLOCK = SEGWIT_FLAG | MSG_FILTERED_BLOCK

      attr_accessor :identifier
      attr_accessor :hash

      KNOWN_IDENTIFIERS = [MSG_TX, MSG_BLOCK, MSG_FILTERED_BLOCK, MSG_CMPCT_BLOCK, MSG_WTX, MSG_WITNESS_TX,
                           MSG_WITNESS_BLOCK, MSG_FILTERED_WITNESS_BLOCK].freeze

      # A type which is not known is kept as it is, and is left for the receiver to ignore, as Bitcoin Core does.
      # @param [Integer] identifier The type of the inventory, a 32 bit unsigned integer.
      # @param [String] hash The hash with hex format.
      # @raise [Bitcoin::Message::Error] If +identifier+ is not a 32 bit unsigned integer.
      def initialize(identifier, hash)
        unless identifier.is_a?(Integer) && identifier.between?(0, 0xffffffff)
          raise Error, "invalid type identifier specified. identifier = #{identifier}"
        end
        @identifier = identifier
        @hash = hash
      end

      # parse inventory payload
      def self.parse_from_payload(payload)
        raise Error, 'invalid inventory size.' if payload.bytesize != 36
        identifier = payload[0..3].unpack1('V')
        hash = payload[4..-1].bth # internal byte order
        new(identifier, hash)
      end

      def to_payload
        [identifier].pack('V') << hash.htb
      end

      def block?
        [MSG_BLOCK, MSG_WITNESS_BLOCK, MSG_FILTERED_WITNESS_BLOCK].include?(identifier)
      end

      # Whether the type of this inventory is one this library knows.
      # @return [Boolean]
      def known?
        KNOWN_IDENTIFIERS.include?(identifier)
      end

    end
  end
end
