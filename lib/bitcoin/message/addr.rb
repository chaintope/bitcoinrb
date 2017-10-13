require 'ipaddr'

module Bitcoin
  module Message

    # addr message
    # https://bitcoin.org/en/developer-reference#addr
    class Addr < Base

      COMMAND = 'addr'

      attr_reader :addrs

      def initialize(addrs = [])
        @addrs = addrs
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        addr_count = Bitcoin.unpack_var_int_from_io(buf)
        addr = new
        addr_count.times do
          addr.addrs << NetworkAddr.parse_from_payload(buf)
        end
        addr
      end

      def to_payload
        Bitcoin.pack_var_int(addrs.length) << addrs.map(&:to_payload).join
      end

    end

  end
end
