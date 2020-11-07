module Bitcoin

  # Mnemonic code for generating deterministic keys
  # https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
  class Mnemonic

    WORD_DIR = "#{__dir__}/mnemonic/wordlist"

    attr_reader :language

    def initialize(language)
      raise ArgumentError, 'specified language is not supported.' unless Mnemonic.word_lists.include?(language)
      @language = language
    end

    # get support language list
    def self.word_lists
      Dir.glob("#{WORD_DIR}/**.txt").map{|f| f.gsub("#{WORD_DIR}/", '').gsub('.txt', '') }
    end

    # generate entropy from mnemonic word
    # @param [Array[String]] words the array of mnemonic word.
    # @return [String] an entropy with hex format.
    def to_entropy(words)
      word_master = load_words
      mnemonic = words.map do |w|
        index = word_master.index(w.downcase)
        raise IndexError, 'word not found in words list.' unless index
        index.to_s(2).rjust(11, '0')
      end.join
      entropy = mnemonic.slice(0, (mnemonic.length * 32) / 33)
      checksum = mnemonic.gsub(entropy, '')
      raise SecurityError, 'checksum mismatch.' unless checksum == checksum(entropy)
      [entropy].pack('B*').bth
    end

    # generate mnemonic words from entropy.
    # @param [String] entropy an entropy with hex format.
    # @return [Array] the array of mnemonic word.
    def to_mnemonic(entropy)
      raise ArgumentError, 'entropy is empty.' if entropy.nil? || entropy.empty?
      e = entropy.htb.unpack1('B*')
      seed = e + checksum(e)
      mnemonic_index = seed.chars.each_slice(11).map{|i|i.join.to_i(2)}
      word_master = load_words
      mnemonic_index.map{|i|word_master[i]}
    end

    # generate seed from mnemonic
    # if mnemonic protected with passphrase, specify that passphrase.
    # @param [Array] mnemonic a array of mnemonic word.
    # @param [String] passphrase a passphrase which protects mnemonic. the default value is an empty string.
    # @return [String] seed
    def to_seed(mnemonic, passphrase: '')
      to_entropy(mnemonic)
      OpenSSL::PKCS5.pbkdf2_hmac(mnemonic.join(' ').downcase,
                                 'mnemonic' + passphrase, 2048, 64, OpenSSL::Digest::SHA512.new).bth
    end

    # calculate entropy checksum
    # @param [String] entropy an entropy with bit string format
    # @return [String] an entropy checksum with bit string format
    def checksum(entropy)
      b = Bitcoin.sha256([entropy].pack('B*')).unpack1('B*')
      b.slice(0, (entropy.length/32))
    end

    private

    # load word list contents
    def load_words
      File.readlines("#{WORD_DIR}/#{language}.txt").map(&:strip)
    end

  end

end
