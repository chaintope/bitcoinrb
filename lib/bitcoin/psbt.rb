require 'base64'

module Bitcoin

  module PSBT

    autoload :Tx, 'bitcoin/psbt/tx'
    autoload :Input, 'bitcoin/psbt/input'
    autoload :Output, 'bitcoin/psbt/output'
    autoload :KeyOriginInfo, 'bitcoin/psbt/key_origin_info'
    autoload :HDKeyPath, 'bitcoin/psbt/hd_key_path'

    # constants for PSBT
    PSBT_MAGIC_BYTES = 0x70736274
    PSBT_GLOBAL_TYPES = {unsigned_tx: 0x00, xpub: 0x01, ver: 0xfb}
    PSBT_IN_TYPES = {non_witness_utxo: 0x00, witness_utxo: 0x01, partial_sig: 0x02,
                     sighash: 0x03, redeem_script: 0x04, witness_script: 0x05,
                     bip32_derivation: 0x06, script_sig: 0x07, script_witness: 0x08}
    PSBT_OUT_TYPES = {redeem_script: 0x00, witness_script: 0x01, bip32_derivation: 0x02}
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
  end

end
