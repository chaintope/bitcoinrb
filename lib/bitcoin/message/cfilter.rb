module Bitcoin
  module Message

    # cfilter message for BIP-157
    # https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki#cfilter
    class CFilter < Base

      COMMAND = 'cfilter'

      attr_accessor :filter_type
      attr_accessor :block_hash   # little endian
      attr_accessor :filter       # little endian

      def initialize(filter_type, block_hash, filter)
        @filter_type = filter_type
        @block_hash = block_hash
        @filter = filter
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        type = buf.read(1).unpack1("C")
        hash = buf.read(32).bth
        len = Bitcoin.unpack_var_int_from_io(buf)
        filter = buf.read(len).bth
        self.new(type, hash, filter)
      end

      def to_payload
        [filter_type, block_hash].pack('CH*') + Bitcoin.pack_var_string(filter.htb)
      end
    end

  end
end