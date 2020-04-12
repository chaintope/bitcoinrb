module Bitcoin

  # BIP47 payment code
  class PaymentCode < ExtKey
    attr_accessor :x_value

    def initialize
      @prefix = '47'
      @version = '01'
      @features_bits = '00'
      @sign = '02'
      @reserve_field = '0' * 26
    end

    # generate master key from seed.
    # @params [String] seed a seed data with hex format.
    def self.generate_master(seed)
      master_ext_key = super.derive(47, harden=true).derive(0, harden=true).derive(0, harden=true)

      payment_code = PaymentCode.new
      payment_code.depth = master_ext_key.depth
      payment_code.key = master_ext_key.key
      payment_code.x_value = master_ext_key.pub.slice(2...master_ext_key.pub.length) # x of pubkey
      payment_code.chain_code = master_ext_key.chain_code
      payment_code
    end

    def payment_code
      Bitcoin::Base58.encode(row_payment_code + Bitcoin.calc_checksum(row_payment_code))
    end

    # get payment code
    def row_payment_code
      @prefix + @version + @features_bits + @sign + @x_value + @chain_code.unpack('H*').first + @reserve_field
    end

    # get notification address
    def notification_address
      ext_pubkey.derive(0).addr
    end

    # decode base58 encoded payment code
    # @params [String] paymen_code_string base58 encoded payment code
    def self.from_payment_code_string(paymen_code_string)
      hex = Bitcoin::Base58.decode(paymen_code_string)
      row_payment_code = hex[0...-8]
      raise ArgumentError, 'invalid checksum' unless Bitcoin.calc_checksum(row_payment_code) == hex[-8..-1]

      x_value = row_payment_code[8..71]
      chain_code_hex = row_payment_code[72..135]

      payment_code_pubkey = PaymentCode.new
      payment_code_pubkey.depth = 3
      payment_code_pubkey.x_value = x_value
      payment_code_pubkey.chain_code = [chain_code_hex].pack('H*')

      payment_code_pubkey.row_payment_code
    end
  end
end
  