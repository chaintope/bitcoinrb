module Bitcoin
  module Message

    # headers message
    # https://bitcoin.org/en/developer-reference#headers
    class Headers < Base

      COMMAND = 'headers'

      # Array[Bitcoin::BlockHeader]
      attr_accessor :headers

      def initialize(headers = [])
        @headers = headers
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        header_count = Bitcoin.unpack_var_int_from_io(buf)
        h = new
        header_count.times do
          h.headers << Bitcoin::BlockHeader.parse_from_payload(buf.read(80))
          buf.read(1) # read tx count 0x00 (headers message doesn't include any tx.)
        end
        h
      end

      def to_payload
        Bitcoin.pack_var_int(headers.size) << headers.map { |h| h.to_payload << 0x00 }.join
      end

    end

  end
end
