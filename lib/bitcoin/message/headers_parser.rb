module Bitcoin
  module Message

    # Common message parser which handle multiple block headers as a payload.
    module HeadersParser

      def parse_from_payload(payload)
        ver, payload = payload.unpack('Va*')
        size, payload = Bitcoin.unpack_var_int(payload)
        hashes = []
        buf = StringIO.new(payload)
        size.times do
          hashes << buf.read(32).bth
        end
        new(ver, hashes, buf.read(32).bth)
      end

      def to_payload
        [version].pack('V') << Bitcoin.pack_var_int(hashes.length) << hashes.map{|h|h.htb}.join << stop_hash.htb
      end

    end
  end
end