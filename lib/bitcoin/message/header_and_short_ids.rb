module Bitcoin
  module Message
    class HeaderAndShortIDs

      attr_accessor :header
      attr_accessor :nonce
      attr_accessor :shortids
      attr_accessor :prefilledtxn

      def initialize
        @shortids = []
        @prefilledtxn = []
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        ids = self.new
        ids.header = Bitcoin::BlockHeader.parse_from_payload(buf.read(80))
        ids.nonce = buf.read(8).unpack('q*').first
        shortids_len = Bitcoin.unpack_var_int_from_io(buf)
        shortids_len.times do
          ids.shortids << buf.read(6).reverse.bth.to_i(16)
        end
        prefilledtxn_len = Bitcoin.unpack_var_int_from_io(buf)
        prefilledtxn_len.times do
          ids.prefilledtxn << PrefilledTx.parse_from_io(buf)
        end
        ids
      end

      def to_payload
        p = header.to_payload
        p << [nonce].pack('q*')
        p << Bitcoin.pack_var_int(shortids.size)
        p << shortids.map{|id|sprintf('%12x', id).htb.reverse}.join
        p << Bitcoin.pack_var_int(prefilledtxn.size)
        p << prefilledtxn.map(&:to_payload).join
        p
      end

    end
  end
end
