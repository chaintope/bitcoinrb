module Bitcoin
  module Message

    # getcfcheckpt message for BIP-157
    # https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki#getcfcheckpt
    class GetCFCheckpt < Base

      COMMAND = 'getcfcheckpt'

      attr_accessor :filter_type
      attr_accessor :stop_hash    # little endian

      def initialize(filter_type, stop_hash)
        @filter_type = filter_type
        @stop_hash = stop_hash
      end

      def self.parse_from_payload(payload)
        type, hash = payload.unpack('CH*')
        self.new(type, hash)
      end

      def to_payload
        [filter_type, stop_hash].pack('CH*')
      end

    end
  end
end