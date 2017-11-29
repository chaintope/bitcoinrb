module Bitcoin
  module Wallet

    # HD Wallet master seed
    class MasterKey
      extend Bitcoin::Util
      include Bitcoin::Util

      attr_reader :seed
      attr_accessor :iv
      attr_accessor :salt
      attr_accessor :encrypted
      attr_accessor :mnemonic # ephemeral data existing only at initialization

      def initialize(seed, iv: '', salt: '', encrypted: false, mnemonic: nil)
        @mnemonic = mnemonic
        @seed = seed
        @encrypted = encrypted
        @iv = iv
        @salt = salt
      end

      # generate new master key.
      # @return Bitcoin::Wallet::MasterKey
      def self.generate
        entropy = SecureRandom.hex(16)
        mnemonic = Bitcoin::Mnemonic.new('english')
        self.recover_from_words(mnemonic.to_mnemonic(entropy))
      end

      # recover master key from mnemonic word list.
      # @param [Array] words the mnemonic word list.
      # @return Bitcoin::Wallet::MasterKey
      def self.recover_from_words(words)
        mnemonic = Bitcoin::Mnemonic.new('english')
        seed = mnemonic.to_seed(words)
        self.new(seed, mnemonic: words)
      end

      # parse master key raw data
      # @param [String] payload raw data
      # @return [Bitcoin::Wallet::MasterKey]
      def self.parse_from_payload(payload)
        flag, payload = unpack_var_int(payload)
        raise 'encrypted flag is invalid.' unless [0, 1].include?(flag)
        iv, payload = unpack_var_string(payload)
        salt, payload = unpack_var_string(payload)
        seed, payload = unpack_var_string(payload)
        self.new(seed.bth, iv: iv.bth, salt: salt.bth, encrypted: flag == 1)
      end

      # generate payload with following format
      # [encrypted(false:0, true:1)][iv(var str)][salt(var str)][seed(var str)]
      def to_payload
        flg = encrypted ? 1 : 0
        pack_var_int(flg) << [iv, salt, seed].map{|v|pack_var_string(v.htb)}.join
      end

      # get master key
      # @return [Bitcoin::ExtKey] the master key
      def key
        Bitcoin::ExtKey.generate_master(seed)
      end

      private

    end
  end
end
