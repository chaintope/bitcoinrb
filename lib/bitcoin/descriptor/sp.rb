module Bitcoin
  module Descriptor
    # sp() expression for Silent Payment descriptor.
    # Supports both single-argument (spscan/spspend) and two-argument forms.
    # @see https://github.com/bitcoin/bips/blob/master/bip-0392.mediawiki
    class Sp < Expression

      # HRP for spscan/spspend encoding
      SPSCAN_HRP = 'spscan'
      SPSPEND_HRP = 'spspend'
      TSPSCAN_HRP = 'tspscan'
      TSPSPEND_HRP = 'tspspend'

      attr_reader :key_arg
      attr_reader :scan_key
      attr_reader :spend_key

      # Constructor.
      # @param [String] key_or_scan_key Either a spscan/spspend encoded key, or the scan key for two-argument form.
      # @param [String, Expression, nil] spend_key The spend key (for two-argument form) or nil for single-argument form.
      # @raise [ArgumentError] If keys are invalid.
      def initialize(key_or_scan_key, spend_key = nil)
        raise ArgumentError, "key_or_scan_key must be a String." unless key_or_scan_key.is_a?(String)
        unless spend_key.nil? || spend_key.is_a?(String) || spend_key.is_a?(Expression)
          raise ArgumentError, "spend_key must be a String, Expression, or nil."
        end
        if spend_key.nil?
          # Single argument form: spscan or spspend encoded key
          @key_arg = key_or_scan_key
          parse_encoded_key(key_or_scan_key)
        else
          # Two argument form: separate scan and spend keys
          @key_arg = nil
          @scan_key = key_or_scan_key
          @spend_key = spend_key
        end
        validate_keys!
      end

      def type
        :sp
      end

      def top_level?
        true
      end

      def args
        if key_arg
          # Single argument form
          key_arg
        else
          # Two argument form
          spend_arg = spend_key.is_a?(Expression) ? spend_key.to_s : spend_key
          "#{scan_key},#{spend_arg}"
        end
      end

      # Check if this is a single-argument form (spscan/spspend).
      # @return [Boolean]
      def single_key?
        !key_arg.nil?
      end

      # Check if this descriptor has spend private key (spspend form).
      # @return [Boolean]
      def has_spend_private_key?
        return @has_spend_private_key if defined?(@has_spend_private_key)
        if single_key?
          @has_spend_private_key
        else
          # Check if spend_key is a private key
          return false if spend_key.is_a?(Expression)
          begin
            key = extract_pubkey(spend_key)
            !key.priv_key.nil?
          rescue
            false
          end
        end
      end

      # Generate silent payment address.
      # @return [Bech32::SilentPaymentAddr] Silent payment address.
      def to_addr
        Bech32::SilentPaymentAddr.new(
          address_hrp,
          0,
          extracted_scan_pubkey,
          extracted_spend_pubkey
        )
      end

      # Silent payment descriptors do not produce a single script.
      # Use to_address to get the silent payment address.
      # @raise [RuntimeError]
      def to_script
        raise RuntimeError, "sp() descriptor does not produce a fixed script. Use to_address instead."
      end

      private

      # Parse spscan or spspend encoded key.
      # @param [String] encoded_key The encoded key string.
      # @raise [ArgumentError] If the key format is invalid.
      def parse_encoded_key(encoded_key)
        # Handle key origin (e.g., [fingerprint/path]key)
        key_str = encoded_key
        if key_str.start_with?('[')
          key_str = key_str[(key_str.index(']') + 1)..-1]
        end

        # Decode Bech32m (max_length increased for longer spscan/spspend strings)
        hrp, data, spec = Bech32.decode(key_str, 200)
        raise ArgumentError, "Invalid spscan/spspend encoding." unless hrp
        raise ArgumentError, "spscan/spspend must use Bech32m encoding." unless spec == Bech32::Encoding::BECH32M

        # Validate HRP
        valid_hrps = [SPSCAN_HRP, SPSPEND_HRP, TSPSCAN_HRP, TSPSPEND_HRP]
        raise ArgumentError, "Invalid HRP: #{hrp}. Expected one of: #{valid_hrps.join(', ')}" unless valid_hrps.include?(hrp)

        # Check version (first data element should be 0 for version 0)
        raise ArgumentError, "Invalid version." unless data[0] == 0

        # Convert from 5-bit to 8-bit
        payload = Bech32.convert_bits(data[1..-1], 5, 8, false)
        payload_bytes = payload.pack('C*')

        is_spspend = [SPSPEND_HRP, TSPSPEND_HRP].include?(hrp)

        if is_spspend
          # spspend: 32 bytes scan + 32 bytes spend
          raise ArgumentError, "Invalid spspend payload length." unless payload_bytes.bytesize == 64
          scan_priv = payload_bytes[0, 32].bth
          spend_priv = payload_bytes[32, 32].bth
          @scan_key = scan_priv
          @spend_key = spend_priv
          @has_spend_private_key = true
        else
          # spscan: 32 bytes scan + 33 bytes spend pubkey
          raise ArgumentError, "Invalid spscan payload length." unless payload_bytes.bytesize == 65
          scan_priv = payload_bytes[0, 32].bth
          spend_pub = payload_bytes[32, 33].bth
          @scan_key = scan_priv
          @spend_key = spend_pub
          @has_spend_private_key = false
        end
      end

      def validate_keys!
        # Scan key must be a private key
        scan = extracted_scan_key
        raise ArgumentError, "Scan key must be a private key." unless scan.priv_key

        # Validate spend key
        spend = extracted_spend_key
        raise ArgumentError, "Uncompressed keys are not allowed." unless spend.compressed?
      end

      # Get the extracted scan key.
      # @return [Bitcoin::Key] Extracted scan key.
      def extracted_scan_key
        if single_key?
          # scan_key is already a hex private key from spscan/spspend
          Bitcoin::Key.new(priv_key: scan_key)
        else
          extract_pubkey(scan_key)
        end
      end

      # Get the extracted scan public key (compressed, 33 bytes hex).
      # @return [String] Compressed public key hex.
      def extracted_scan_pubkey
        extracted_scan_key.pubkey
      end

      # Get the extracted spend key.
      # @return [Bitcoin::Key] Extracted spend key.
      def extracted_spend_key
        if spend_key.is_a?(MuSig)
          # MuSig returns x-only pubkey, convert to full pubkey
          Bitcoin::Key.from_xonly_pubkey(spend_key.to_hex)
        elsif spend_key.is_a?(Expression)
          spend_key.extracted_key
        elsif single_key? && has_spend_private_key?
          # spspend: spend_key is hex private key
          Bitcoin::Key.new(priv_key: spend_key)
        elsif single_key?
          # spscan: spend_key is hex public key
          Bitcoin::Key.new(pubkey: spend_key)
        else
          extract_pubkey(spend_key)
        end
      end

      # Get the extracted spend public key (compressed, 33 bytes hex).
      # @return [String] Compressed public key hex.
      def extracted_spend_pubkey
        if spend_key.is_a?(MuSig)
          # MuSig aggregated key as compressed pubkey (even y-coordinate assumed)
          '02' + spend_key.to_hex
        else
          extracted_spend_key.pubkey
        end
      end

      # Get HRP for silent payment address based on network.
      # @return [String] HRP (sp for mainnet, tsp for testnet/signet).
      def address_hrp
        case Bitcoin.chain_params.network
        when 'mainnet'
          Bech32::SilentPaymentAddr::HRP_MAINNET
        else
          Bech32::SilentPaymentAddr::HRP_TESTNET
        end
      end
    end
  end
end
