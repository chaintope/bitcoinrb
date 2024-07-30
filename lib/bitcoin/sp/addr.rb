module Bitcoin
  module SilentPayment
    class Addr

      HRP_MAINNET = 'sp'
      HRP_TESTNET = 'tsp'
      MAX_CHARACTERS = 1023

      attr_reader :version
      attr_reader :scan_key
      attr_reader :spend_key

      # Constructor.
      # @param [Bitcoin::Key] scan_key
      # @param [Bitcoin::Key] spend_key
      def initialize(version, scan_key:, spend_key:)
        raise ArgumentError, "version must be integer." unless version.is_a?(Integer)
        raise ArgumentError, "scan_key must be Bitcoin::Key." unless scan_key.is_a?(Bitcoin::Key)
        raise ArgumentError, "spend_key must be Bitcoin::Key." unless spend_key.is_a?(Bitcoin::Key)
        raise ArgumentError, "version '#{version}' is unsupported." unless version.zero?

        @version = version
        @scan_key = scan_key
        @spend_key = spend_key
      end

      # Parse silent payment address.
      # @param [String] A silent payment address.
      # @return [Bitcoin::SilentPayment::Addr]
      def self.from_string(addr)
        raise ArgumentError, "addr must be string." unless addr.is_a?(String)
        hrp, data, spec = Bech32.decode(addr, MAX_CHARACTERS)
        unless hrp == Bitcoin.chain_params.mainnet? ? HRP_MAINNET : HRP_TESTNET
          raise ArgumentError, "The specified hrp is different from the current network HRP."
        end
        raise ArgumentError, "spec must be bech32m." unless spec == Bech32::Encoding::BECH32M

        ver = data[0]
        payload = Bech32.convert_bits(data[1..-1], 5, 8, false).pack("C*")
        scan_key = Bitcoin::Key.new(pubkey: payload[0...33].bth, key_type: Bitcoin::Key::TYPES[:compressed])
        spend_key = Bitcoin::Key.new(pubkey: payload[33..-1].bth, key_type: Bitcoin::Key::TYPES[:compressed])
        Addr.new(ver, scan_key: scan_key, spend_key: spend_key)
      end

      # Get silent payment address.
      # @return [String]
      def to_s
        hrp = Bitcoin.chain_params.mainnet? ? HRP_MAINNET : HRP_TESTNET
        payload = [scan_key.pubkey + spend_key.pubkey].pack("H*").unpack('C*')
        Bech32.encode(hrp, [version] + Bech32.convert_bits(payload, 8, 5), Bech32::Encoding::BECH32M)
      end

    end
  end
end