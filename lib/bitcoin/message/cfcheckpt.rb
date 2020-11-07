module Bitcoin
  module Message

    # cfcheckpt message for BIP-157
    # https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki#cfcheckpt
    class CFCheckpt < Base

      COMMAND = 'cfcheckpt'

      attr_accessor :filter_type
      attr_accessor :stop_hash      # little endian
      attr_accessor :filter_headers # little endian

      def initialize(filter_type, stop_hash, filter_headers)
        @filter_type = filter_type
        @stop_hash = stop_hash
        @filter_headers = filter_headers
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        type = buf.read(1).unpack1('C')
        hash = buf.read(32).unpack1('H*')
        count = Bitcoin.unpack_var_int_from_io(buf)
        headers = count.times.map{buf.read(32).bth}
        self.new(type, hash, headers)
      end

      def to_payload
        [filter_type, stop_hash].pack('CH*') +
            Bitcoin.pack_var_int(filter_headers.size) + filter_headers.map(&:htb).join
      end
    end

  end
end