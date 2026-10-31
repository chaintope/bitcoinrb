module Bitcoin
  module Message

    # Common message parser which handle multiple block headers as a payload.
    module HeadersParser

      def parse_from_payload(payload)
        raise Bitcoin::Message::Error, 'Payload is too short.' if payload.bytesize < 4
        ver, payload = payload.unpack('Va*')
        size, payload = Bitcoin.unpack_var_int(payload)
        raise Bitcoin::Message::Error, "#{self::COMMAND} locator size #{size} exceeds #{MAX_LOCATOR_SZ}." if size > MAX_LOCATOR_SZ
        hashes = []
        buf = StringIO.new(payload)
        size.times do
          hashes << Bitcoin.read_exact(buf, 32).bth
        end
        new(ver, hashes, Bitcoin.read_exact(buf, 32).bth)
      end

      def to_payload
        [version].pack('V') << Bitcoin.pack_var_int(hashes.length) << hashes.map{|h|h.htb}.join << stop_hash.htb
      end

    end
  end
end