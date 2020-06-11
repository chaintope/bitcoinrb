module Bitcoin
  module Message

    # getcfheaders message for BIP-157
    # https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki#getcfheaders
    class GetCFHeaders < Base
      include CFParser
      extend CFParser

      COMMAND = 'getcfheaders'

      attr_accessor :filter_type
      attr_accessor :start_height
      attr_accessor :stop_hash    # little endian

      def initialize(filter_type, start_height, stop_hash)
        @filter_type = filter_type
        @start_height = start_height
        @stop_hash = stop_hash
      end

    end
  end
end