module Bitcoin
  module Message

    # filterload message
    # https://bitcoin.org/en/developer-reference#filterload
    class FilterLoad < Base

      COMMAND = 'filterload'

      BLOOM_UPDATE_NONE = 0
      BLOOM_UPDATE_ALL = 1
      BLOOM_UPDATE_P2PUBKEY_ONLY = 2

      attr_accessor :filter # bin format
      attr_accessor :func_count
      attr_accessor :tweak
      attr_accessor :flag

      def initialize(filter, func_count, tweak = 0, flag = BLOOM_UPDATE_ALL)
        @filter = filter
        @func_count = func_count
        @tweak = tweak
        @flag = flag
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        filter_count = Bitcoin.unpack_var_int_from_io(buf)
        filter = buf.read(filter_count).unpack('C*')
        func_count = buf.read(4).unpack('V').first
        tweak = buf.read(4).unpack('V').first
        flag = buf.read(1).unpack('C').first
        new(filter, func_count, tweak, flag)
      end

      def to_payload
        Bitcoin.pack_var_int(filter.size) << filter.pack('C*') << [func_count, tweak, flag].pack('VVC')
      end

    end

  end
end
