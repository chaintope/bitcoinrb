module Bitcoin

  # Deterministic Entropy From BIP32 Keychains
  # https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki
  class BIP85Entropy

    BIP85_PATH = 83696968 + HARDENED_THRESHOLD

    include Bitcoin::KeyPath

    attr_reader :root_key #hex format

    # Import root key.
    # @param [String] base58 master bip32 root key.
    # @return [Bitcoin::BIP85Entropy]
    def self.from_base58(base58)
      key = Bitcoin::ExtKey.from_base58(base58)
      self.new(key)
    end

    # derive entropy
    # @param [String] path derive path.
    # @return [Tuple(String, Object)] a tuple of entropy with hex format and results depending the application.
    def derive(path)
      raise ArgumentError, "Invalid BIP85 path format." unless path.start_with?("m/83696968'")
      derived_key = root_key
      parse_key_path(path).each{|num| derived_key = derived_key.derive(num)}
      derived_key = derived_key.priv
      entropy = Bitcoin.hmac_sha512("bip-entropy-from-k", derived_key.htb).bth
      app_no = path.split('/')[2]
      case app_no
      when "39'"
        bip39_entropy(path, entropy)
      when "2'"
        hd_seed_entropy(entropy)
      when "32'"
        xprv_entropy(entropy)
      else
        [entropy, entropy]
      end
    end

    private

    def initialize(root_key)
      @root_key = root_key
    end

    # derive BIP39 entropy.
    def bip39_entropy(path, entropy)
      params = path.split('/')
      word_len = params[4]
      language = code_to_language(params[3])
      entropy = case word_len
                when "12'"
                  entropy[0...32]
                when "18'"
                  entropy[0...48]
                when "24'"
                  entropy[0...64]
                else
                  raise ArgumentError, "Word length #{word_len} does not supported."
                end
      mnemonic = Bitcoin::Mnemonic.new(language)
      [entropy, mnemonic.to_mnemonic(entropy)]
    end

    # derive HD-Seed WIF entropy.
    def hd_seed_entropy(entropy)
      result = entropy[0...64]
      [result, Bitcoin::Key.new(priv_key: result).to_wif]
    end

    # derive xprv entropy
    def xprv_entropy(entropy)
      chaincode = entropy[0...64]
      private_key = Bitcoin::Key.new(priv_key: entropy[64..-1])
      ext_key = Bitcoin::ExtKey.new
      ext_key.key = private_key
      ext_key.chain_code = chaincode.htb
      ext_key.depth = 0
      ext_key.number = 0
      ext_key.parent_fingerprint = Bitcoin::ExtKey::MASTER_FINGERPRINT
      [entropy, ext_key.to_base58]
    end

    # convert language code to language string.
    def code_to_language(code)
      case code
      when "0'"
        "english"
      when "1'"
        "japanese"
      when "3'"
        "spanish"
      when "4'"
        "chinese_simplified"
      when "5'"
        "chinese_traditional"
      when "6'"
        "french"
      when "7'"
        "italian"
      else
        raise ArgumentError, "bitcoinrb does not support language: #{code}"
      end
    end

  end

end