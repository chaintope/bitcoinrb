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
      MSG_WITNESS_TX = SEGWIT_FLAG | MSG_TX
      MSG_WITNESS_BLOCK = SEGWIT_FLAG | MSG_BLOCK
      MSG_FILTERED_WITNESS_BLOCK = SEGWIT_FLAG | MSG_FILTERED_BLOCK

      attr_accessor :identifier
      attr_accessor :hash

      def initialize(identifier, hash)
        raise Error, "invalid type identifier specified. identifier = #{identifier}" unless valid_identifier?(identifier)
        @identifier = identifier
        @hash = hash
      end

      # parse inventory payload
      def self.parse_from_payload(payload)
        raise Error, 'invalid inventory size.' if payload.bytesize != 36
        identifier = payload[0..4].unpack('V').first
        hash = payload[4..-1].reverse.bth # internal byte order
        new(identifier, hash)
      end

      def to_payload
        [identifier].pack('V') << hash.htb.reverse
      end

      def block?
        [MSG_BLOCK, MSG_WITNESS_BLOCK, MSG_FILTERED_WITNESS_BLOCK].include?(identifier)
      end

      private

      def valid_identifier?(identifier)
        [MSG_TX, MSG_BLOCK, MSG_FILTERED_BLOCK, MSG_CMPCT_BLOCK, MSG_WITNESS_TX,
         MSG_WITNESS_BLOCK, MSG_FILTERED_WITNESS_BLOCK].include?(identifier)
      end

    end
  end
end
