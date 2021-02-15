module Bitcoin
  module Message

    # addrv2 message class.
    # https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki
    class AddrV2 < Base

      COMMAND = 'addrv2'

      attr_reader :addrs

      def initialize(addrs = [])
        @addrs = addrs
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        addr_count = Bitcoin.unpack_var_int_from_io(buf)
        v2 = new
        addr_count.times do
          v2.addrs << NetworkAddr.parse_from_payload(buf, type: NetworkAddr::TYPE[:addr_v2])
        end
        v2
      end

      def to_payload
        buf = Bitcoin.pack_var_int(addrs.size)
        buf << (addrs.map { |a| a.to_payload(type: NetworkAddr::TYPE[:addr_v2])}.join)
      end

    end

  end
end