module Bitcoin
  module Wallet

    # HD Wallet master seed
    class MasterKey
      include Bitcoin::HexConverter
      extend Bitcoin::Util
      include Bitcoin::Util
      include Bitcoin::KeyPath

      attr_reader :seed
      attr_accessor :salt
      attr_accessor :encrypted
      attr_accessor :mnemonic # ephemeral data existing only at initialization

      def initialize(seed, salt: '', encrypted: false, mnemonic: nil)
        @mnemonic = mnemonic
        @seed = seed
        @encrypted = encrypted
        @salt = salt
      end

      # generate new master key.
      # @return Bitcoin::Wallet::MasterKey
      def self.generate
        entropy = SecureRandom.hex(32)
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
        salt, payload = unpack_var_string(payload)
        salt = '' unless salt
        seed, payload = unpack_var_string(payload)
        self.new(seed.bth, salt: salt.bth, encrypted: flag == 1)
      end

      # generate payload with following format
      # [encrypted(false:0, true:1)][salt(var str)][seed(var str)]
      def to_payload
        flg = encrypted ? 1 : 0
        pack_var_int(flg) << [salt, seed].map{|v|pack_var_string(v.htb)}.join
      end

      # get master key
      # @return [Bitcoin::ExtKey] the master key
      def key
        raise 'seed is encrypted. please decrypt the seed.' if encrypted
        Bitcoin::ExtKey.generate_master(seed)
      end

      # derive child key using derivation path.
      # @return [Bitcoin::ExtKey]
      def derive(path)
        derived_key = key
        parse_key_path(path).each{|num| derived_key = derived_key.derive(num)}
        derived_key
      end

      # encrypt seed
      def encrypt(passphrase)
        raise 'The wallet is already encrypted.' if encrypted
        @salt = SecureRandom.hex(16)
        enc = OpenSSL::Cipher.new('AES-256-CBC')
        enc.encrypt
        enc.key, enc.iv = key_iv(enc, passphrase)
        encrypted_data = ''
        encrypted_data << enc.update(seed)
        encrypted_data << enc.final
        @seed = encrypted_data
        @encrypted = true
      end

      # decrypt seed
      def decrypt(passphrase)
        raise 'The wallet is not encrypted.' unless encrypted
        dec = OpenSSL::Cipher.new('AES-256-CBC')
        dec.decrypt
        dec.key, dec.iv = key_iv(dec, passphrase)
        decrypted_data = ''
        decrypted_data << dec.update(seed)
        decrypted_data << dec.final
        @seed = decrypted_data
        @encrypted = false
        @salt = ''
      end

      private

      def key_iv(enc, passphrase)
        key_iv = OpenSSL::PKCS5.pbkdf2_hmac_sha1(passphrase, salt, 2000, enc.key_len + enc.iv_len)
        [key_iv[0, enc.key_len], key_iv[enc.key_len, enc.iv_len]]
      end

    end
  end
end
