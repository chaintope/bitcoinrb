module Bitcoin

  module Descriptor

    include Bitcoin::Opcodes

    # Script thin wrapper class for descriptor.
    class Expression

      # Type of Expression
      module Type
        PK = :pk
        PKH = :pkh
        SH = :sh
        WPKH = :wpkh
        WSH = :wsh
        MULTI = :multi
        SORTEDMULTI = :sortedmulti
        COMBO = :combo
        RAW = :raw
        ADDR = :addr

        # Supported types.
        # @return [Array]
        def self.all
          [PK, PKH, SH, WPKH, WSH, MULTI, SORTEDMULTI, COMBO, RAW, ADDR]
        end

        # Check whether +type+ is supproted.
        # @return [Boolean]
        def self.include?(type)
          all.include?(type)
        end

      end

      attr_reader :type
      attr_reader :payload

      # Constructor
      # @param [Symbol] type
      # @param [Bitcoin::Script or Bitcoin::Descriptor::Expression] payload
      def initialize(type, payload)
        raise ArgumentError, "Type '#{type}' is unsupported." unless Type.include?(type)
        if type == :combo
          payload.each do |exp|
            raise ArgumentError, "The payload of a combo must be an array of expressions." unless exp.is_a?(Expression)
          end
        else
          unless payload.is_a?(Bitcoin::Script) || payload.is_a?(Expression)
            raise ArgumentError, "payload must be Bitcoin::Script or Bitcoin::Descriptor::Expression."
          end
        end
        @type = type
        @payload = payload
      end

      # Get hex string for this script.
      # @return [String]
      # @raise [RuntimeError] see #to_script
      def to_hex
        raise RuntimeError, "combo() has multiple script, it cannot be directly converted to a hex value." if type == :combo
        to_script.to_hex
      end

      # Convert to Bitcoin::Script
      # @return [Bitcoin::Script or Array] If combo, return array of Script.
      # @raise [RuntimeError] If this expression is invalid.
      def to_script
        return payload.map(&:to_script) if type == :combo
        script = payload.is_a?(Expression) ? payload.to_script : payload
        if script.multisig?
          pubkey_count = script.get_pubkeys.length
          raise RuntimeError, "Cannot have #{pubkey_count} pubkeys in bare multisig; only at most 3 pubkeys." if pubkey_count > 3
        end
        script
      end
    end

    # generate P2PK output for the given public key.
    # @param [String] key private key or public key with hex format
    # @return [Bitcoin::Descriptor::Expression] P2PK script.
    def pk(key)
      Expression.new(:pk, Script.new << extract_pubkey(key) << OP_CHECKSIG)
    end

    # generate P2PKH output for the given public key.
    # @param [String] key private key or public key with hex format.
    # @return [Bitcoin::Descriptor::Expression] P2PKH script.
    def pkh(key)
      Expression.new(:pkh, Script.to_p2pkh(Bitcoin.hash160(extract_pubkey(key))))
    end

    # generate P2PKH output for the given public key.
    # @param [String] key private key or public key with hex format.
    # @return [Bitcoin::Descriptor::Expression] P2WPKH script.
    def wpkh(key)
      pubkey = extract_pubkey(key)
      raise ArgumentError, "Uncompressed key are not allowed." unless compressed_key?(pubkey)
      Expression.new(:wpkh, Script.to_p2wpkh(Bitcoin.hash160(pubkey)))
    end

    # generate P2SH embed the argument.
    # @param [Bitcoin::Descriptor::Expression] exp script expression to be embed.
    # @return [Bitcoin::Descriptor::Expression] P2SH script.
    def sh(exp)
      validate_top_level!(exp)
      raise ArgumentError, 'A function is needed within P2SH.' unless exp.is_a?(Bitcoin::Descriptor::Expression)
      script_size = exp.payload.size
      if script_size > Bitcoin::MAX_SCRIPT_ELEMENT_SIZE
        raise ArgumentError,
              "P2SH script is too large, #{script_size} bytes is larger than #{Bitcoin::MAX_SCRIPT_ELEMENT_SIZE} bytes."
      end
      Expression.new(:sh, exp.payload.to_p2sh)
    end

    # generate P2WSH embed the argument.
    # @param [Bitcoin::Descriptor::Expression] exp script expression to be embed.
    # @return [Bitcoin::Descriptor::Expression] P2WSH script.
    def wsh(exp)
      validate_top_level!(exp)
      raise ArgumentError, 'A function is needed within P2WSH.' unless exp.is_a?(Bitcoin::Descriptor::Expression)
      case exp.type
      when :wpkh, :wsh
        raise ArgumentError, "Can only have #{exp.type}() at top level or inside sh()."
      end
      raise ArgumentError, "Uncompressed key are not allowed." if exp.payload.get_pubkeys.any?{|p|!compressed_key?(p)}
      Expression.new(:wsh, Script.to_p2wsh(exp.payload))
    end

    # An alias for the collection of `pk(KEY)` and `pkh(KEY)`.
    # If the key is compressed, it also includes `wpkh(KEY)` and `sh(wpkh(KEY))`.
    # @param [String] key private key or public key with hex format.
    # @return [Bitcoin::Descriptor::Expression]
    def combo(key)
      result = [pk(key), pkh(key)]
      pubkey = extract_pubkey(key)
      if compressed_key?(pubkey)
        result << wpkh(key)
        result << sh(result.last)
      end
      Expression.new(:combo, result)
    end

    # generate multisig output for given keys.
    # @param [Integer] threshold the threshold of multisig.
    # @param [Array[String]] keys an array of keys.
    # @return [Bitcoin::Descriptor::Expression] multisig script.
    def multi(threshold, *keys, sort: false)
      raise ArgumentError, "Multisig threshold '#{threshold}' is not valid." unless threshold.is_a?(Integer)
      raise ArgumentError, 'Multisig threshold cannot be 0, must be at least 1.' unless threshold > 0
      raise ArgumentError, 'Multisig threshold cannot be larger than the number of keys.' if threshold > keys.size
      raise ArgumentError, "Multisig must have between 1 and #{Bitcoin::MAX_PUBKEYS_PER_MULTISIG} keys, inclusive." if keys.size > Bitcoin::MAX_PUBKEYS_PER_MULTISIG
      pubkeys = keys.map{|key| extract_pubkey(key) }
      Expression.new(:multi, Script.to_multisig_script(threshold, pubkeys, sort: sort))
    end

    # generate sorted multisig output for given keys.
    # @param [Integer] threshold the threshold of multisig.
    # @param [Array[String]] keys an array of keys.
    # @return [Bitcoin::Descriptor::Expression] multisig script.
    def sortedmulti(threshold, *keys)
      Expression.new(:sortedmulti, multi(threshold, *keys, sort: true))
    end

    private

    # extract public key from KEY format.
    # @param [String] key KEY string.
    # @return [String] public key.
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
        key = derive_path(key, paths, true) if paths
      elsif key.start_with?('xpub')
        key = Bitcoin::ExtPubkey.from_base58(key)
        key = derive_path(key, paths, false) if paths
      else
        begin
          key = Bitcoin::Key.from_wif(key)
        rescue ArgumentError
          key_type =  compressed_key?(key) ? Bitcoin::Key::TYPES[:compressed] : Bitcoin::Key::TYPES[:uncompressed]
          key = Bitcoin::Key.new(pubkey: key, key_type: key_type)
        end
      end
      key = key.is_a?(Bitcoin::Key) ? key : key.key
      raise ArgumentError, Errors::Messages::INVALID_PUBLIC_KEY unless key.fully_valid_pubkey?
      key.pubkey
    end

    def compressed_key?(key)
      %w(02 03).include?(key[0..1]) && [key].pack("H*").bytesize == 33
    end

    def derive_path(key, paths, is_private)
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

    def validate_top_level!(exp)
      return unless exp.is_a?(Expression)
      case exp.type
      when Expression::Type::COMBO
        raise ArgumentError, 'Can only have combo() at top level.'
      when :sh
        raise ArgumentError, 'Can only have sh() at top level.'
      end
    end
  end

end