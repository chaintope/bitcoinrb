module Bitcoin
  module Message

    # filterload message
    # https://bitcoin.org/en/developer-reference#filterload
    class FilterLoad < Base

      COMMAND = 'filterload'

      BLOOM_UPDATE_NONE = 0
      BLOOM_UPDATE_ALL = 1
      BLOOM_UPDATE_P2PUBKEY_ONLY = 2

      attr_accessor :filter
      attr_accessor :flag

      def initialize(filter, flag = BLOOM_UPDATE_ALL)
        @filter = filter
        @flag = flag
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        filter_count = Bitcoin.unpack_var_int_from_io(buf)
        filter = buf.read(filter_count).unpack('C*')
        func_count = buf.read(4).unpack1('V')
        tweak = buf.read(4).unpack1('V')
        flag = buf.read(1).unpack1('C')
        FilterLoad.new(Bitcoin::BloomFilter.new(filter, func_count, tweak), flag)
      end

      def to_payload
        Bitcoin.pack_var_int(filter.filter.size) << filter.filter.pack('C*') << [filter.hash_funcs, filter.tweak, flag].pack('VVC')
      end

    end

  end
end
