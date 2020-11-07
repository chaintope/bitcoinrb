module Bitcoin
  module Message

    # cfheaders message for BIP-157
    # https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki#cfheaders
    class CFHeaders < Base

      COMMAND = 'cfheaders'

      attr_accessor :filter_type
      attr_accessor :stop_hash            # little endian
      attr_accessor :prev_filter_header   # little endian
      attr_accessor :filter_hashes        # little endian

      def initialize(filter_type, stop_hash, prev_filter_header, filter_hashes)
        @filter_type = filter_type
        @stop_hash = stop_hash
        @prev_filter_header = prev_filter_header
        @filter_hashes = filter_hashes
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        type = buf.read(1).unpack1("C")
        hash = buf.read(32).bth
        header = buf.read(32).bth
        count = Bitcoin.unpack_var_int_from_io(buf)
        hashes = count.times.map{buf.read(32).bth}
        self.new(type, hash, header, hashes)
      end

      def to_payload
        [filter_type].pack('C') + stop_hash.htb + prev_filter_header.htb +
            Bitcoin.pack_var_int(filter_hashes.size) + filter_hashes.map(&:htb).join
      end

    end

  end
end