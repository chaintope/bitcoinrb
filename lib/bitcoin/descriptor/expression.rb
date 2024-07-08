module Bitcoin
  module Descriptor
    # Expression for descriptor.
    class Expression

      # Get expression type.
      # @return [Symbol]
      def type
        raise NotImplementedError
      end

      # Convert to bitcoin script
      # @return [Bitcoin::Script]
      def to_script
        raise NotImplementedError
      end

      # Whether this is top level or not.
      # @return [Boolean]
      def top_level?
        raise NotImplementedError
      end

      # Get args for this expression.
      # @return [String] args
      def args
        raise NotImplementedError
      end

      # Get descriptor string.
      # @param [Boolean] checksum If true, append checksum.
      # @return [String] Descriptor string.
      def to_s(checksum: false)
        desc = "#{type.to_s}(#{args})"
        checksum ? Checksum.descsum_create(desc) : desc
      end

      # Convert to bitcoin script as hex string.
      # @return [String]
      def to_hex
        to_script.to_hex
      end

      # Check whether +key+ is compressed public key or not.
      # @return [Boolean]
      def compressed_key?(key)
        %w(02 03).include?(key[0..1]) && [key].pack("H*").bytesize == 33
      end

      # Extract public key from KEY format.
      # @param [String] key KEY string.
      # @return [Bitcoin::Key] public key.
      def extract_pubkey(key)
        if key.start_with?('[') # BIP32 fingerprint
          raise ArgumentError, "Multiple ']' characters found for a single pubkey." if key.count('[') > 1 || key.count(']') > 1
          info = key[1...key.index(']')]
          fingerprint, *paths = info.split('/')
          raise ArgumentError, "Fingerprint '#{fingerprint}' is not hex." unless fingerprint.valid_hex?
          raise ArgumentError, "Fingerprint '#{fingerprint}' is not 4 bytes." unless fingerprint.size == 8
          key = key[(key.index(']') + 1)..-1]
        else
          raise ArgumentError, 'Invalid key origin.' if key.include?(']')
        end

        # check BIP32 derivation path
        key, *paths = key.split('/')

        raise ArgumentError, "No key provided." unless key

        if key.start_with?('xprv')
          key = Bitcoin::ExtKey.from_base58(key)
          key = derive_path(key, paths) if paths
        elsif key.start_with?('xpub')
          key = Bitcoin::ExtPubkey.from_base58(key)
          key = derive_path(key, paths) if paths
        else
          begin
            key = Bitcoin::Key.from_wif(key)
          rescue ArgumentError
            key = if key.length == 64
                    Bitcoin::Key.from_xonly_pubkey(key)
                  else
                    key_type = compressed_key?(key) ? Bitcoin::Key::TYPES[:compressed] : Bitcoin::Key::TYPES[:uncompressed]
                    Bitcoin::Key.new(pubkey: key, key_type: key_type)
                  end
          end
        end
        key = key.is_a?(Bitcoin::Key) ? key : key.key
        raise ArgumentError, Errors::Messages::INVALID_PUBLIC_KEY unless key.fully_valid_pubkey?
        key
      end

      # Derive key using +paths+.
      # @param [Bitcoin::ExtKey or Bitcoin::ExtPubkey] key
      # @param [String] paths derivation path.
      # @return [Bitcoin::Key]
      def derive_path(key, paths)
        is_private = key.is_a?(Bitcoin::ExtKey)
        paths.each do |path|
          raise ArgumentError, 'xpub can not derive hardened key.' if !is_private && path.end_with?("'")
          if is_private
            hardened = path.end_with?("'")
            path = hardened ? path[0..-2] : path
            raise ArgumentError, 'Key path value is not a valid value.' unless path =~ /^[0-9]+$/
            raise ArgumentError, 'Key path value is out of range.' if !hardened && path.to_i >= Bitcoin::HARDENED_THRESHOLD
            key = key.derive(path.to_i, hardened)
          else
            raise ArgumentError, 'Key path value is not a valid value.' unless path =~ /^[0-9]+$/
            raise ArgumentError, 'Key path value is out of range.' if path.to_i >= Bitcoin::HARDENED_THRESHOLD
            key = key.derive(path.to_i)
          end
        end
        key
      end

      def ==(other)
        return false unless other.is_a?(Expression)
        type == other.type && to_script == other.to_script
      end
    end
  end
end