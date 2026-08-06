module Bitcoin
  module Wallet

    # HD Wallet master seed
    class MasterKey
      include Bitcoin::HexConverter
      extend Bitcoin::Util
      include Bitcoin::Util
      include Bitcoin::KeyPath

      # The seed is not encrypted.
      NOT_ENCRYPTED = 0
      # AES-256-CBC with a key derived by PBKDF2-HMAC-SHA1. Only supported to load a wallet
      # which was already encrypted, #encrypt always writes ENCRYPTED_V2.
      ENCRYPTED_V1 = 1
      # AES-256-GCM with a key derived by PBKDF2-HMAC-SHA512.
      ENCRYPTED_V2 = 2

      ENCRYPTION_VERSIONS = [ENCRYPTED_V1, ENCRYPTED_V2]

      V1_KDF_ROUNDS = 2000
      # Rounds for PBKDF2-HMAC-SHA512, which take roughly 100 ms.
      KDF_ROUNDS = 210_000

      SALT_SIZE = 16
      GCM_IV_SIZE = 12
      GCM_TAG_SIZE = 16

      attr_reader :seed
      attr_accessor :salt
      attr_accessor :encrypted
      # The encryption version of +seed+, nil unless encrypted.
      attr_reader :encryption_version
      attr_accessor :mnemonic # ephemeral data existing only at initialization

      def initialize(seed, salt: '', encrypted: false, mnemonic: nil, encryption_version: nil)
        @mnemonic = mnemonic
        @seed = seed
        @encrypted = encrypted
        @encryption_version = encrypted ? (encryption_version || ENCRYPTED_V2) : nil
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
        raise 'encrypted flag is invalid.' unless [NOT_ENCRYPTED, *ENCRYPTION_VERSIONS].include?(flag)
        salt, payload = unpack_var_string(payload)
        salt = '' unless salt
        seed, payload = unpack_var_string(payload)
        self.new(seed.bth, salt: salt.bth,
                 encrypted: flag != NOT_ENCRYPTED, encryption_version: flag)
      end

      # generate payload with following format
      # [encryption version(not encrypted:0, v1:1, v2:2)][salt(var str)][seed(var str)]
      def to_payload
        flg = encrypted ? encryption_version : NOT_ENCRYPTED
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

      # Encrypt the seed with +passphrase+.
      # The stored seed is [IV(12 bytes)][auth tag(16 bytes)][ciphertext].
      # @param [String] passphrase
      def encrypt(passphrase)
        raise 'The wallet is already encrypted.' if encrypted
        salt = SecureRandom.bytes(SALT_SIZE)
        iv = SecureRandom.bytes(GCM_IV_SIZE)
        enc = OpenSSL::Cipher.new('AES-256-GCM')
        enc.encrypt
        enc.key = derive_key(passphrase, salt, enc.key_len)
        enc.iv = iv
        encrypted_data = enc.update(seed) << enc.final
        @salt = salt.bth
        @seed = (iv + enc.auth_tag(GCM_TAG_SIZE) + encrypted_data).bth
        @encryption_version = ENCRYPTED_V2
        @encrypted = true
      end

      # Decrypt the seed with +passphrase+.
      # @param [String] passphrase
      # @raise [ArgumentError] If +passphrase+ is wrong or the encrypted seed is corrupted.
      def decrypt(passphrase)
        raise 'The wallet is not encrypted.' unless encrypted
        @seed = encryption_version == ENCRYPTED_V1 ? decrypt_v1(passphrase) : decrypt_v2(passphrase)
        @encrypted = false
        @encryption_version = nil
        @salt = ''
      end

      private

      # Derive an encryption key from +passphrase+.
      # @param [String] passphrase
      # @param [String] salt Salt with binary format.
      # @param [Integer] length Key length in bytes.
      # @return [String] Derived key with binary format.
      def derive_key(passphrase, salt, length)
        OpenSSL::PKCS5.pbkdf2_hmac(passphrase, salt, KDF_ROUNDS, length, OpenSSL::Digest::SHA512.new)
      end

      # Decrypt a seed stored by ENCRYPTED_V2.
      # A wrong passphrase is rejected by the GCM authentication tag.
      def decrypt_v2(passphrase)
        data = seed.htb
        raise ArgumentError, 'The encrypted seed is too short.' if data.bytesize <= GCM_IV_SIZE + GCM_TAG_SIZE
        dec = OpenSSL::Cipher.new('AES-256-GCM')
        dec.decrypt
        dec.key = derive_key(passphrase, salt.htb, dec.key_len)
        dec.iv = data[0...GCM_IV_SIZE]
        dec.auth_tag = data[GCM_IV_SIZE...(GCM_IV_SIZE + GCM_TAG_SIZE)]
        decrypt_with(dec, data[(GCM_IV_SIZE + GCM_TAG_SIZE)..-1])
      end

      # Decrypt a seed stored by ENCRYPTED_V1.
      # That scheme has no authentication, so a wrong passphrase is only detected by the CBC
      # padding and passes with a probability of about 1/256, yielding a garbage seed.
      def decrypt_v1(passphrase)
        dec = OpenSSL::Cipher.new('AES-256-CBC')
        dec.decrypt
        # The salt was passed to PBKDF2 as the hex string it is stored as, not as its bytes.
        key_iv = OpenSSL::PKCS5.pbkdf2_hmac_sha1(passphrase, salt, V1_KDF_ROUNDS, dec.key_len + dec.iv_len)
        dec.key = key_iv[0, dec.key_len]
        dec.iv = key_iv[dec.key_len, dec.iv_len]
        decrypt_with(dec, seed.htb)
      end

      def decrypt_with(dec, data)
        dec.update(data) << dec.final
      rescue OpenSSL::Cipher::CipherError
        raise ArgumentError, 'Invalid passphrase.'
      end

    end
  end
end
