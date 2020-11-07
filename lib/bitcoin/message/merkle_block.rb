module Bitcoin
  module Message

    # merckleblock message
    # https://bitcoin.org/en/developer-reference#merkleblock
    class MerkleBlock < Base

      COMMAND = 'merkleblock'

      attr_accessor :header
      attr_accessor :tx_count
      attr_accessor :hashes
      attr_accessor :flags

      def initialize
        @hashes = []
      end

      def self.parse_from_payload(payload)
        m = new
        buf = StringIO.new(payload)
        m.header = Bitcoin::BlockHeader.parse_from_payload(buf.read(80))
        m.tx_count = buf.read(4).unpack1('V')
        hash_count = Bitcoin.unpack_var_int_from_io(buf)
        hash_count.times do
          m.hashes << buf.read(32).bth
        end
        flag_count = Bitcoin.unpack_var_int_from_io(buf)
        # A sequence of bits packed eight in a byte with the least significant bit first.
        m.flags = buf.read(flag_count).bth
        m
      end

      def to_payload
        header.to_payload << [tx_count].pack('V') << Bitcoin.pack_var_int(hashes.size) <<
            hashes.map(&:htb).join << Bitcoin.pack_var_int(flags.htb.bytesize) << flags.htb
      end

    end

  end
end
