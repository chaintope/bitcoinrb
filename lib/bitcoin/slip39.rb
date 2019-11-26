module Bitcoin
  module SLIP39

    WORDS = File.readlines("#{__dir__}/slip39/wordlist/english.txt").map(&:strip)

    module_function

    def bits_to_bytes(n)
      (n + 7) / 8
    end

    def bits_to_words(n)
      (n + RADIX_BITS - 1) / RADIX_BITS
    end

    # The length of the radix in bits.
    RADIX_BITS = 10
    # The number of words in the wordlist.
    RADIX = 2 ** RADIX_BITS
    # The length of the random identifier in bits.
    ID_LENGTH_BITS = 15
    # The length of the iteration exponent in bits.
    ITERATION_EXP_LENGTH_BITS = 5
    # The length of the random identifier and iteration exponent in words.
    ID_EXP_LENGTH_WORDS = bits_to_words(ID_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS)
    # The maximum number of shares that can be created.
    MAX_SHARE_COUNT = 16
    # The length of the RS1024 checksum in words.
    CHECKSUM_LENGTH_WORDS = 3
    # The length of the digest of the shared secret in bytes.
    DIGEST_LENGTH_BYTES = 4
    # The customization string used in the RS1024 checksum and in the PBKDF2 salt.
    CUSTOMIZATION_STRING = 'shamir'.bytes
    # The length of the mnemonic in words without the share value.
    METADATA_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS
    # The minimum allowed entropy of the master secret.
    MIN_STRENGTH_BITS = 128
    # The minimum allowed length of the mnemonic in words.
    MIN_MNEMONIC_LENGTH_WORDS = METADATA_LENGTH_WORDS + bits_to_words(MIN_STRENGTH_BITS)
    # The minimum number of iterations to use in PBKDF2.
    BASE_ITERATION_COUNT = 10000
    # The number of rounds to use in the Feistel cipher.
    ROUND_COUNT = 4
    # The index of the share containing the shared secret.
    SECRET_INDEX = 255
    # The index of the share containing the digest of the shared secret.
    DIGEST_INDEX = 254

    EXP_TABLE = [
        1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19,
        53, 95, 225, 56, 72, 216, 115, 149, 164, 247, 2, 6, 10, 30, 34,
        102, 170, 229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217, 112, 144,
        171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184,
        211, 110, 178, 205, 76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241,
        8, 24, 40, 120, 136, 131, 158, 185, 208, 107, 189, 220, 127, 129, 152,
        179, 206, 73, 219, 118, 154, 181, 196, 87, 249, 16, 48, 80, 240, 11,
        29, 39, 105, 187, 214, 97, 163, 254, 25, 43, 125, 135, 146, 173, 236,
        47, 113, 147, 174, 233, 32, 96, 160, 251, 22, 58, 78, 210, 109, 183,
        194, 93, 231, 50, 86, 250, 21, 63, 65, 195, 94, 226, 61, 71, 201,
        64, 192, 91, 237, 44, 116, 156, 191, 218, 117, 159, 186, 213, 100, 172,
        239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 155, 182, 193, 88,
        232, 35, 101, 175, 234, 37, 111, 177, 200, 67, 197, 84, 252, 31, 33,
        99, 165, 244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202, 69, 207,
        74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14, 18,
        54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23,
        57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246
    ]

    LOG_TABLE = [
        0, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3,
        100, 4, 224, 14, 52, 141, 129, 239, 76, 113, 8, 200, 248, 105, 28,
        193, 125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166, 114, 154, 201,
        9, 120, 101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53,
        147, 218, 142, 150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241,
        64, 70, 131, 56, 102, 221, 253, 48, 191, 6, 139, 98, 179, 37, 226,
        152, 34, 136, 145, 16, 126, 110, 72, 195, 163, 182, 30, 66, 58, 107,
        40, 84, 250, 133, 61, 186, 43, 121, 10, 21, 155, 159, 94, 202, 78,
        212, 172, 229, 243, 115, 167, 87, 175, 88, 168, 80, 244, 234, 214, 116,
        79, 174, 233, 213, 231, 230, 173, 232, 44, 215, 117, 122, 235, 22, 11,
        245, 89, 203, 95, 176, 156, 169, 81, 160, 127, 12, 246, 111, 23, 196,
        73, 236, 216, 67, 31, 45, 164, 118, 123, 183, 204, 187, 62, 90, 251,
        96, 177, 134, 59, 82, 161, 108, 170, 85, 41, 157, 151, 178, 135, 144,
        97, 190, 220, 252, 188, 149, 207, 205, 55, 63, 91, 209, 83, 57, 132,
        60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171, 68, 17, 146,
        217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165, 103, 74, 237,
        222, 197, 49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7
    ]

    autoload :SSS, 'bitcoin/slip39/sss'
    autoload :Share, 'bitcoin/slip39/share'

  end
end