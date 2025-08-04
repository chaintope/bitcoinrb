require 'spec_helper'

RSpec.describe Bitcoin::Descriptor::MultiA, network: :mainnet do

  include Bitcoin::Descriptor

  describe "BIP387" do
    it do
      expect(tr('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1',
                multi_a(1, 'KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy')).to_hex).
        to eq('5120eb5bd3894327d75093891cc3a62506df7d58ec137fcd104cdd285d67816074f3')
      expect(tr('a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd',
                multi_a(1, '669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0')).to_hex).
        to eq('5120eb5bd3894327d75093891cc3a62506df7d58ec137fcd104cdd285d67816074f3')
      key = '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'
      multi_keys = %w[[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0]
      expect(tr(key, multi_a(2, *multi_keys)).to_hex).to eq('51202eea93581594a43c0c8423b70dc112e5651df63984d108d4fc8ccd3b63b4eafa')
      expect(tr(key, sortedmulti_a(2, *multi_keys)).to_hex).to eq('512016fa6a6ba7e98c54b5bf43b3144912b78a61b60b02f6a74172b8dcb35b12bc30')
      expect(tr(key, sortedmulti_a(2,
                                   "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0",
                                   "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0/0/0")
             ).to_hex).to eq('5120abd47468515223f58a1a18edfde709a7a2aab2b696d59ecf8c34f0ba274ef772')
      desc_multi_a = "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,multi_a(2,xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0,xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/0,xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/0'))"
      multi_a = Bitcoin::Descriptor.parse(desc_multi_a)
      expect(multi_a.to_hex).to eq('5120e4c8f2b0a7d3a688ac131cb03248c0d4b0a59bbd4f37211c848cfbd22a981192')
      expect(multi_a.to_s).to eq(desc_multi_a)

      key = '03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0'
      expect{multi_a(1, key).to_hex}.
        to raise_error(RuntimeError, 'Can only have multi_a/sortedmulti_a inside tr().')
      expect{Bitcoin::Descriptor.parse("multi_a(1,#{key})")}.
        to raise_error(ArgumentError, 'Can only have multi_a/sortedmulti_a inside tr().')
      expect{sortedmulti_a(1, key).to_hex}.
        to raise_error(RuntimeError, 'Can only have multi_a/sortedmulti_a inside tr().')
      expect{Bitcoin::Descriptor.parse("sortedmulti_a(1,#{key})")}.
        to raise_error(ArgumentError, 'Can only have multi_a/sortedmulti_a inside tr().')
      expect{sh(multi_a(1, key))}.to raise_error(ArgumentError, 'Can only have multi_a/sortedmulti_a inside tr().')
      expect{sh(sortedmulti_a(1, key))}.to raise_error(ArgumentError, 'Can only have multi_a/sortedmulti_a inside tr().')
      expect{wsh(multi_a(1, key))}.to raise_error(ArgumentError, 'Can only have multi_a/sortedmulti_a inside tr().')
      expect{wsh(sortedmulti_a(1, key))}.to raise_error(ArgumentError, 'Can only have multi_a/sortedmulti_a inside tr().')
      key = '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd'
      expect{multi_a('a', key)}.to raise_error(ArgumentError, "Multisig threshold 'a' is not valid.")
      expect{sortedmulti_a('a', key)}.to raise_error(ArgumentError, "Multisig threshold 'a' is not valid.")
      expect{multi_a(0, key)}.to raise_error(ArgumentError, "Multisig threshold cannot be 0, must be at least 1.")
      expect{sortedmulti_a(0, key)}.to raise_error(ArgumentError, "Multisig threshold cannot be 0, must be at least 1.")
      uncompressed_key = '04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235'
      expect{multi_a(1, uncompressed_key)}.to raise_error(ArgumentError, "Uncompressed key are not allowed.")
      expect{sortedmulti_a(1, uncompressed_key)}.to raise_error(ArgumentError, "Uncompressed key are not allowed.")
      expect{multi_a(3,
                     'L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1',
                     '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss')}
        .to raise_error(ArgumentError, "Multisig threshold cannot be larger than the number of keys.")
      expect{sortedmulti_a(3,
                           'L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1',
                           '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss')}
        .to raise_error(ArgumentError, "Multisig threshold cannot be larger than the number of keys.")
    end
  end

end