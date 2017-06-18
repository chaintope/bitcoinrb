module Bitcoin
  module Message
    # inventory class. inventory is a part of message.
    # https://bitcoin.org/en/developer-reference#term-inventory
    class Inventory

      IDENTIFIER_MSG_TX = 1
      IDENTIFIER_MSG_BLOCK = 2
      IDENTIFIER_MSG_FILTERED_BLOCK = 3

      attr_accessor :identifier
      attr_accessor :hash

      def initialize(identifier, hash)
        raise Error, "invalid type identifier specified. identifier = #{identifier}" unless [IDENTIFIER_MSG_TX, IDENTIFIER_MSG_BLOCK,IDENTIFIER_MSG_FILTERED_BLOCK].include?(identifier)
        @identifier = identifier
        @hash = hash
      end

      # parse inventory payload
      def self.parse_from_payload(payload)
        raise Error, 'invalid inventory size.' if payload.bytesize != 36
        identifier = payload[0..4].unpack('V').first
        raise Error, "invalid type identifier specified. identifier = #{identifier}" unless [IDENTIFIER_MSG_TX, IDENTIFIER_MSG_BLOCK,IDENTIFIER_MSG_FILTERED_BLOCK].include?(identifier)
        hash = payload[4..-1].reverse.bth # internal byte order
        new(identifier, hash)
      end

      def to_payload
        [identifier].pack('V') << hash.htb.reverse
      end

    end
  end
end
