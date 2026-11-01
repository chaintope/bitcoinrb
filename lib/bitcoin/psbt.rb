module Bitcoin

  module PSBT

    autoload :Tx, 'bitcoin/psbt/tx'
    autoload :Input, 'bitcoin/psbt/input'
    autoload :Output, 'bitcoin/psbt/output'
    autoload :KeyOriginInfo, 'bitcoin/psbt/key_origin_info'
    autoload :HDKeyPath, 'bitcoin/psbt/hd_key_path'
    autoload :Proprietary, 'bitcoin/psbt/proprietary'

    # constants for PSBT
    PSBT_MAGIC_BYTES = 0x70736274
    PSBT_GLOBAL_TYPES = {
      unsigned_tx: 0x00,
      xpub: 0x01,
      ver: 0xfb,
      proprietary: 0xfc
    }
    PSBT_IN_TYPES = {
      non_witness_utxo: 0x00,
      witness_utxo: 0x01,
      partial_sig: 0x02,
      sighash: 0x03,
      redeem_script: 0x04,
      witness_script: 0x05,
      bip32_derivation: 0x06,
      script_sig: 0x07,
      script_witness: 0x08,
      ripemd160: 0x0a,
      sha256: 0x0b,
      hash160: 0x0c,
      hash256: 0x0d,
      tap_key_sig: 0x13,
      tap_script_sig: 0x14,
      tap_leaf_script: 0x15,
      tap_bip32_derivation: 0x16,
      tap_internal_key: 0x17,
      tap_merkle_root: 0x18,
      proprietary: 0xfc
    }
    PSBT_OUT_TYPES = {
      redeem_script: 0x00,
      witness_script: 0x01,
      bip32_derivation: 0x02,
      tap_internal_key: 0x05,
      tap_tree: 0x06,
      tap_bip32_derivation: 0x07,
      proprietary: 0xfc
    }
    PSBT_SEPARATOR = 0x00

    SUPPORT_VERSION = 0

    module_function

    # Combine one field of two PSBT maps the way a BIP-174 combiner does: a value present on one side only is
    # taken, equal values are kept, and different values are a conflict.
    # @param [Object] a The value of one map, or nil.
    # @param [Object] b The value of the other map, or nil.
    # @param [String] name The field, for the error message, e.g. "Input's non_witness_utxo".
    # @return [Object] the combined value.
    # @raise [ArgumentError] If both are present and differ.
    def self.merge_field(a, b, name)
      return b if a.nil?
      return a if b.nil?
      raise ArgumentError, "The Partially Signed #{name} are different." unless a == b
      a
    end

    # Parse the public key of a PSBT record, which is 33 bytes compressed or 65 bytes uncompressed.
    # @param [String] hex The public key with hex format.
    # @return [Bitcoin::Key]
    # @raise [ArgumentError] If +hex+ is not a valid public key.
    def self.parse_pubkey(hex)
      unless hex.is_a?(String) && hex.valid_hex? && [Bitcoin::Key::COMPRESSED_PUBLIC_KEY_SIZE, Bitcoin::Key::PUBLIC_KEY_SIZE].include?(hex.size / 2)
        raise ArgumentError, Errors::Messages::INVALID_PUBLIC_KEY
      end
      key_type = hex.size == Bitcoin::Key::PUBLIC_KEY_SIZE * 2 ? Bitcoin::Key::TYPES[:uncompressed] : Bitcoin::Key::TYPES[:compressed]
      key = Bitcoin::Key.new(pubkey: hex, key_type: key_type)
      raise ArgumentError, Errors::Messages::INVALID_PUBLIC_KEY unless key.fully_valid_pubkey?
      key
    end

    # Combine two lists of proprietary records, keeping the first record for a key which appears in both.
    # @return [Array[Bitcoin::PSBT::Proprietary]]
    def self.merge_proprietaries(a, b)
      (a + b).uniq(&:key)
    end

    # Check the value of a tap bip32 derivation record (BIP-371): a compact size count of leaf hashes,
    # the hashes, then a fingerprint and the 4 byte indexes of the path.
    # @param [String] value the value with binary format.
    # @raise [ArgumentError]
    def self.validate_tap_bip32_derivation!(value)
      buf = StringIO.new(value)
      count = Bitcoin.unpack_var_int_from_io(buf)
      raise ArgumentError, 'Invalid tap bip32 derivation value.' if count.nil? || count * 32 > buf.size - buf.pos
      rest = buf.size - buf.pos - count * 32
      raise ArgumentError, 'Invalid length for HD key path.' if rest < 4 || (rest - 4) % 4 != 0
    end

    def self.serialize_to_vector(key_type, key: nil, value: nil)
      key_len = Bitcoin.pack_var_int(key_type).bytesize
      key_len += key.bytesize if key
      s = Bitcoin.pack_var_int(key_len) << Bitcoin.pack_var_int(key_type)
      s << key if key
      s << Bitcoin.pack_var_int(value.bytesize) << value
      s
    end

    # Load PSBT from file.
    # @param [String] path File path of PSBT.
    # @return [Bitcoin::PSBT::Tx] PSBT object.
    def load_from_file(path)
      raise ArgumentError, 'File not found' unless File.exist?(path)
      Bitcoin::PSBT::Tx.parse_from_payload(File.read(path))
    end
  end

end
