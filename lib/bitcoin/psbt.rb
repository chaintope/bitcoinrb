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

    def self.serialize_to_vector(key_type, key: nil, value: nil)
      key_len = key_type.itb.bytesize
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
