module Bitcoin
  module PSBT

    class KeyOriginInfo

      include Bitcoin::KeyPath

      attr_reader :fingerprint # String hex format
      attr_reader :key_paths    # Array[Integer]

      def initialize(fingerprint: nil, key_paths: [])
        @fingerprint = fingerprint
        @key_paths = key_paths
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        self.new(fingerprint: buf.read(4).bth, key_paths: buf.read.unpack('I*'))
      end

      def to_payload
        fingerprint.htb + key_paths.pack('I*')
      end

      def to_h
        {fingerprint: fingerprint, key_paths: to_key_path(key_paths)}
      end

      def to_s
        to_h.to_s
      end
    end
  end
end
