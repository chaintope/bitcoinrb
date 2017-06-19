module Bitcoin
  module Message

    # block message
    # https://bitcoin.org/en/developer-reference#getblocks
    class GetBlocks < Base

      DEFAULT_STOP_HASH = "00"*32

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

      def self.parse_from_payload(payload)
        ver, payload = payload.unpack('Va*')
        size, payload = Bitcoin.unpack_var_int(payload)
        hashes = []
        buf = StringIO.new(payload)
        size.times do
          hashes << buf.read(32).reverse.bth
        end
        new(ver, hashes, buf.read(32).reverse.bth)
      end

      def command
        'getblocks'
      end

      def to_payload
        [version].pack('V') << Bitcoin.pack_var_int(hashes.length) << hashes.map{|h|h.htb.reverse}.join << stop_hash.htb.reverse
      end

    end

  end
end
