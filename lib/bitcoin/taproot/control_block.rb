module Bitcoin
  module Taproot
    class ControlBlock
      include Bitcoin::HexConverter

      attr_accessor :parity
      attr_accessor :leaf_ver
      attr_accessor :internal_key
      attr_accessor :paths

      # @param [Integer] parity
      # @param [Integer] leaf_ver
      # @param [String] internal_key public key with hex format.
      # @param [Array[String]] paths array of hash values of sibling nodes in the tree that serve as proof of inclusion
      def initialize(parity, leaf_ver, internal_key, paths = [])
        @parity = parity
        @leaf_ver = leaf_ver
        @internal_key = internal_key
        @paths = paths
      end

      # @raise [Bitcoin::Taproot::Error]
      # @return [Bitcoin::Taproot::ControlBlock]
      def self.parse_from_payload(payload)
        raise Bitcoin::Taproot::Error, 'Invalid data length for path in Control Block' unless (payload.bytesize - 33) % 32 == 0
        control, internal_key, paths = payload.unpack('Ca32a*')
        parity = control & 1
        leaf_ver = control - parity
        raw_paths = StringIO.new(paths)
        paths = (paths.bytesize / 32).times.map { raw_paths.read(32).bth }
        ControlBlock.new(parity, leaf_ver, internal_key.bth, paths)
      end

      # Convert to payload.
      # @return [String] payload with binary format.
      def to_payload
        [parity + leaf_ver].pack("C") + internal_key.htb + paths.map(&:htb).join
      end
    end
  end
end