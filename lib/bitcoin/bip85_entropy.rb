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

    # The alphabet of the Base85 encoding BIP-85 uses, which is the one of RFC 1924 and Python's base64.b85encode.
    BASE85_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~'.freeze

    # derive entropy
    # The applications of BIP-85 are understood: BIP39 (39'), HD-Seed WIF (2'), XPRV (32'), HEX (128169'),
    # PWD BASE64 (707764') and PWD BASE85 (707785'). For any other application the 64 byte entropy is returned
    # as it is.
    # @param [String] path derive path. Every index has to be hardened.
    # @return [Tuple(String, Object)] a tuple of entropy with hex format and results depending the application.
    # @raise [ArgumentError] If +path+ is not a BIP-85 path, or a parameter of the application is out of range.
    def derive(path)
      raise ArgumentError, "Invalid BIP85 path format." unless path.start_with?("m/83696968'")
      numbers = parse_key_path(path)
      raise ArgumentError, 'Every index of a BIP85 path must be hardened.' unless numbers.all? { |n| n >= HARDENED_THRESHOLD }
      derived_key = root_key
      numbers.each{|num| derived_key = derived_key.derive(num)}
      derived_key = derived_key.priv
      entropy = Bitcoin.hmac_sha512("bip-entropy-from-k", derived_key.htb).bth
      app_no, *params = numbers[1..-1].map { |n| n - HARDENED_THRESHOLD }
      case app_no
      when 39
        bip39_entropy(params, entropy)
      when 2
        validate_params!(params, 1)
        hd_seed_entropy(entropy)
      when 32
        validate_params!(params, 1)
        xprv_entropy(entropy)
      when 128169
        hex_entropy(params, entropy)
      when 707764
        pwd_base64_entropy(params, entropy)
      when 707785
        pwd_base85_entropy(params, entropy)
      else
        [entropy, entropy]
      end
    end

    private

    def initialize(root_key)
      @root_key = root_key
    end

    # Check that the application has +count+ parameters after its number, the last one being the index.
    def validate_params!(params, count)
      raise ArgumentError, "Invalid BIP85 path format." unless params.size == count
    end

    # derive BIP39 entropy.
    # @param [Array[Integer]] params language, word count and index.
    def bip39_entropy(params, entropy)
      validate_params!(params, 3)
      language = code_to_language(params[0])
      words = params[1]
      unless Bitcoin::Mnemonic::WORD_COUNTS.include?(words)
        raise ArgumentError, "Word length #{words}' does not supported."
      end
      entropy = entropy[0...(words / 3 * 8)] # 12 words use 128 bits, and every 3 words add 32 bits.
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

    # derive HEX entropy: the first num_bytes bytes, 16 <= num_bytes <= 64.
    # @param [Array[Integer]] params num_bytes and index.
    def hex_entropy(params, entropy)
      validate_params!(params, 2)
      num_bytes = params[0]
      raise ArgumentError, "num_bytes #{num_bytes}' must be between 16 and 64." unless num_bytes.between?(16, 64)
      result = entropy[0...(num_bytes * 2)]
      [result, result]
    end

    # derive PWD BASE64: the first pwd_len characters of the Base64 encoding of the entropy, 20 <= pwd_len <= 86.
    # @param [Array[Integer]] params pwd_len and index.
    def pwd_base64_entropy(params, entropy)
      validate_params!(params, 2)
      pwd_len = params[0]
      raise ArgumentError, "pwd_len #{pwd_len}' must be between 20 and 86." unless pwd_len.between?(20, 86)
      [entropy, Base64.strict_encode64(entropy.htb)[0, pwd_len]]
    end

    # derive PWD BASE85: the first pwd_len characters of the Base85 encoding of the entropy, 10 <= pwd_len <= 80.
    # @param [Array[Integer]] params pwd_len and index.
    def pwd_base85_entropy(params, entropy)
      validate_params!(params, 2)
      pwd_len = params[0]
      raise ArgumentError, "pwd_len #{pwd_len}' must be between 10 and 80." unless pwd_len.between?(10, 80)
      [entropy, base85(entropy.htb)[0, pwd_len]]
    end

    # Base85 encode +data+, whose size is a multiple of 4 bytes, as Python's base64.b85encode does.
    def base85(data)
      data.unpack('N*').flat_map { |word| 5.times.map { |i| BASE85_ALPHABET[(word / 85**(4 - i)) % 85] } }.join
    end

    # convert language code to language string.
    def code_to_language(code)
      case code
      when 0
        "english"
      when 1
        "japanese"
      when 3
        "spanish"
      when 4
        "chinese_simplified"
      when 5
        "chinese_traditional"
      when 6
        "french"
      when 7
        "italian"
      else
        raise ArgumentError, "bitcoinrb does not support language: #{code}'"
      end
    end

  end

end