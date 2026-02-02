module Bitcoin
  module Message
    # sendtxrcncl message for BIP-330.
    # https://github.com/bitcoin/bips/blob/master/bip-0330.mediawiki
    class SendTxRcncl < Base
      include Schnorr::Util
      COMMAND = 'sendtxrcncl'

      attr_reader :version
      attr_reader :salt

      # @param [Integer] version
      # @param [Integer] salt
      def initialize(version, salt)
        raise ArgumentError, "version must be integer." unless version.is_a?(Integer)
        raise ArgumentError, "salt must be integer." unless salt.is_a?(Integer)
        raise ArgumentError, "version must be positive number." unless version > 0
        raise ArgumentError, "version is out of range." if version < 0 || version > 0xffffffff
        raise ArgumentError, "salt is out of range." if salt < 0 || salt > 0xffffffffffffffff
        @version = version
        @salt = salt
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        version, salt = buf.read(16).unpack('VQ<')
        SendTxRcncl.new(version, salt)
      end

      def to_payload
        [version, salt].pack('VQ<')
      end
    end
  end
end