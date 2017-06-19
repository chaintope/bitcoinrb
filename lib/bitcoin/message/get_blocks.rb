module Bitcoin
  module Message

    # block message
    # https://bitcoin.org/en/developer-reference#getblocks
    class GetBlocks < Base
      include HeadersParser
      extend HeadersParser

      COMMAND = 'getblocks'

      # protocol version
      attr_accessor :version

      # block header hashes
      attr_accessor :hashes

      attr_accessor :stop_hash

      def initialize(version, hashes, stop_hash = DEFAULT_STOP_HASH)
        @version = version
        @hashes = hashes
        @stop_hash = stop_hash
      end

    end

  end
end
