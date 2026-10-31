module Bitcoin
  module Message

    # headers message
    # https://bitcoin.org/en/developer-reference#headers
    class Headers < Base

      COMMAND = 'headers'

      # The most headers one message may carry. Bitcoin Core sends this many for one getheaders and
      # rejects a message with more (MAX_HEADERS_RESULTS).
      MAX_HEADERS_RESULTS = 2000

      # Array[Bitcoin::BlockHeader]
      attr_accessor :headers

      def initialize(headers = [])
        @headers = headers
      end

      # @raise [Bitcoin::Message::Error] If the payload is truncated or carries more headers than allowed.
      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        header_count = Bitcoin.unpack_var_int_from_io(buf)
        raise Bitcoin::Message::Error, 'Invalid headers payload. header count is missing.' if header_count.nil?
        raise Bitcoin::Message::Error, "Invalid headers payload. header count #{header_count} exceeds #{MAX_HEADERS_RESULTS}." if header_count > MAX_HEADERS_RESULTS
        h = new
        header_count.times do
          header = buf.read(80)
          raise Bitcoin::Message::Error, 'Invalid headers payload. header is truncated.' if header.nil? || header.bytesize < 80
          h.headers << Bitcoin::BlockHeader.parse_from_payload(header)
          # The tx count is a CompactSize, which Bitcoin Core reads and ignores since a headers message
          # carries no tx. Reading a single byte here misaligned every header behind a longer encoding.
          tx_count = Bitcoin.unpack_var_int_from_io(buf)
          raise Bitcoin::Message::Error, 'Invalid headers payload. tx count is missing.' if tx_count.nil?
        end
        h
      end

      def to_payload
        Bitcoin.pack_var_int(headers.size) << headers.map { |h| h.to_payload << 0x00 }.join
      end

    end

  end
end
