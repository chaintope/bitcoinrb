module Bitcoin
  module Message

    # sendcmpct message
    # https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki
    class SendCmpct < Base

      COMMAND = 'sendcmpct'

      MODE_HIGH = 1
      MODE_LOW = 0

      attr_accessor :mode
      attr_accessor :version
      # TODO support version 2

      def initialize(mode = MODE_HIGH, version = 1)
        @mode = mode
        @version = version
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        mode = buf.read(1).unpack1('c')
        version = buf.read(8).unpack1('Q')
        new(mode, version)
      end

      def to_payload
        [mode, version].pack('cQ')
      end

      def high?
        mode == 1
      end

      def low?
        mode.zero?
      end
    end

  end
end
