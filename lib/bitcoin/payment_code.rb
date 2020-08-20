module Bitcoin

  # BIP47 payment code
  class PaymentCode < ExtKey

    include Bitcoin::HexConverter

    attr_accessor :x_value
    attr_accessor :sign

    VERSION_BYTE = '47'
    SUPPORT_VERSIONS = ['01']
    SUPPORT_SIGNS = ['02', '03']

    def initialize
      @version = '01'
      @features_bits = '00'
      @reserve_field = '0' * 26
    end

    # generate master key from seed.
    # @params [String] seed a seed data with hex format.
    def self.generate_master(seed)
      master_ext_key = super.derive(47, harden=true).derive(0, harden=true).derive(0, harden=true)
      compressed_pubkey = master_ext_key.pub

      payment_code = PaymentCode.new
      payment_code.depth = master_ext_key.depth
      payment_code.key = master_ext_key.key
      payment_code.sign = compressed_pubkey[0..1]
      payment_code.x_value = compressed_pubkey[2..-1]
      payment_code.chain_code = master_ext_key.chain_code
      payment_code
    end

    # Base58 encoded payment code
    def to_base58
      payment_code_with_version_byte = VERSION_BYTE + to_hex
      Bitcoin::Base58.encode(payment_code_with_version_byte + Bitcoin.calc_checksum(payment_code_with_version_byte))
    end

    # serialize payment code
    def to_payload
      @version.htb << @features_bits.htb << @sign.htb << @x_value.htb << @chain_code << @reserve_field.htb
    end

    # get notification address
    def notification_address
      ext_pubkey.derive(0).addr
    end

    # decode base58 encoded payment code
    # @params [String] base58_payment_code base58 encoded payment code
    def self.from_base58(base58_payment_code)
      hex = Bitcoin::Base58.decode(base58_payment_code)
      version = hex[2..3]
      sign = hex[6..7]
      public_key = hex[8..71]
      payment_code = hex[0...-8]

      raise ArgumentError, 'invalid version byte' unless hex[0..1] == VERSION_BYTE
      raise ArgumentError, 'invalid version' unless PaymentCode.support_version?(version)
      raise ArgumentError, 'invalid sign' unless PaymentCode.support_sign?(sign)
      raise ArgumentError, Errors::Messages::INVALID_PUBLIC_KEY unless Bitcoin::Key.new(priv_key: nil, pubkey: sign + public_key).fully_valid_pubkey?
      raise ArgumentError, Errors::Messages::INVALID_CHECKSUM unless Bitcoin.calc_checksum(payment_code) == hex[-8..-1]

      x_value = payment_code[8..71]
      chain_code_hex = payment_code[72..135]

      payment_code_pubkey = PaymentCode.new
      payment_code_pubkey.depth = 3
      payment_code_pubkey.sign = sign
      payment_code_pubkey.x_value = x_value
      payment_code_pubkey.chain_code = [chain_code_hex].pack('H*')

      payment_code_pubkey.to_payload
    end

    # check whether +version+ is supported version bytes.
    def self.support_version?(version)
      SUPPORT_VERSIONS.include?(version)
    end

    # check whether +sign+ is supported version bytes.
    def self.support_sign?(sign)
      SUPPORT_SIGNS.include?(sign)
    end

  end

end
  