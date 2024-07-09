require 'spec_helper'

describe Bitcoin::Descriptor, network: :mainnet do

  include Bitcoin::Descriptor

  describe 'Test Vector' do
    it 'should be passe' do
      # Basic single-key compressed
      combo = %w(2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac 76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac 00149a1c78a507689f6f54b847ad1cef1e614ee23f1e a91484ab21b1b2fd065d4504ff693d832434b6108d7b87)
      expect(combo('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1').to_scripts.map(&:to_hex)).to eq(combo)
      expect(combo('03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd').to_scripts.map(&:to_hex)).to eq(combo)
      expect(pk("L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1").to_hex).to eq('2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac')
      expect(pk("03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd").to_hex).to eq('2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac')
      expect(pkh("[deadbeef/1/2'/3/4']L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1").to_hex).to eq('76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac')
      expect(sh(wpkh('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')).to_hex).to eq('a91484ab21b1b2fd065d4504ff693d832434b6108d7b87')
      expect{sh(wpkh('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY2'))}.to raise_error(ArgumentError, Bitcoin::Errors::Messages::INVALID_PUBLIC_KEY)
      expect{pkh("deadbeef/1/2'/3/4']L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1")}.to raise_error(ArgumentError, 'Invalid key origin.')
      expect{pkh("[deadbeef]/1/2'/3/4']L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1")}.to raise_error(ArgumentError, "Multiple ']' characters found for a single pubkey.")

      # Basic single-key uncompressed
      combo = %w(4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235ac 76a914b5bd079c4d57cc7fc28ecf8213a6b791625b818388ac)
      expect(combo('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss').to_scripts.map(&:to_hex)).to eq(combo)
      expect(combo('04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235').to_scripts.map(&:to_hex)).to eq(combo)
      expect(pk("5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss").to_hex).to eq('4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235ac')
      expect(pk("04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235").to_hex).to eq('4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235ac')
      expect(pkh('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss').to_hex).to eq('76a914b5bd079c4d57cc7fc28ecf8213a6b791625b818388ac')
      expect(pkh('04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235').to_hex).to eq('76a914b5bd079c4d57cc7fc28ecf8213a6b791625b818388ac')
      expect{wpkh('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss')}.to raise_error(ArgumentError, 'Uncompressed key are not allowed.')
      expect{wsh(pk('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss'))}.to raise_error(ArgumentError, 'Uncompressed key are not allowed.')
      expect{sh(wpkh('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss'))}.to raise_error(ArgumentError, 'Uncompressed key are not allowed.')

      # Some unconventional single-key constructions
      expect(sh(pk('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')).to_hex).to eq('a9141857af51a5e516552b3086430fd8ce55f7c1a52487')
      expect(sh(pkh('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')).to_hex).to eq('a9141a31ad23bf49c247dd531a623c2ef57da3c400c587')
      expect(wsh(pk('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')).to_hex).to eq('00202e271faa2325c199d25d22e1ead982e45b64eeb4f31e73dbdf41bd4b5fec23fa')
      expect(wsh(pkh('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')).to_hex).to eq('0020338e023079b91c58571b20e602d7805fb808c22473cbc391a41b1bd3a192e75b')
      expect(sh(wsh(pk('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1'))).to_hex).to eq('a91472d0c5a3bfad8c3e7bd5303a72b94240e80b6f1787')
      expect(sh(wsh(pkh('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1'))).to_hex).to eq('a914b61b92e2ca21bac1e72a3ab859a742982bea960a87')

      # Versions with BIP32 derivations
      combo = %w(2102d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0ac 76a91431a507b815593dfc51ffc7245ae7e5aee304246e88ac 001431a507b815593dfc51ffc7245ae7e5aee304246e a9142aafb926eb247cb18240a7f4c07983ad1f37922687)
      expect(combo('[01234567]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc').to_scripts.map(&:to_hex)).to eq(combo)
      expect(combo('[01234567]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL').to_scripts.map(&:to_hex)).to eq(combo)
      expect(pk('xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0').to_hex).to eq('210379e45b3cf75f9c5f9befd8e9506fb962f6a9d185ac87001ec44a8d3df8d4a9e3ac')
      expect(pk('xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0').to_hex).to eq('210379e45b3cf75f9c5f9befd8e9506fb962f6a9d185ac87001ec44a8d3df8d4a9e3ac')
      expect(pkh("xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0").to_hex).to eq('76a914ebdc90806a9c4356c1c88e42216611e1cb4c1c1788ac')
      expect{combo("[012345678]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc")}.to raise_error(ArgumentError, "Fingerprint '012345678' is not 4 bytes.")
      expect{pkh("xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483648")}.to raise_error(ArgumentError, 'Key path value is out of range.')
      expect{pkh("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483648")}.to raise_error(ArgumentError, 'Key path value is out of range.')
      expect{pkh("xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/1aa")}.to raise_error(ArgumentError, 'Key path value is not a valid value.')
      expect{pkh("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1aa")}.to raise_error(ArgumentError, 'Key path value is not a valid value.')

      # Multisig constructions
      expect(multi(1, 'L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1', '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss').to_hex).to eq('512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea23552ae')
      expect(multi(1, '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd', '04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235').to_hex).to eq('512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea23552ae')
      expect(sortedmulti(1, 'L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1', '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss').to_hex).to eq('512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea23552ae')
      expect(sortedmulti(1, '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd', '04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235').to_hex).to eq('512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea23552ae')
      expect(sortedmulti(1, '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss', 'L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1').to_hex).to eq('512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea23552ae')
      expect(sortedmulti(1, '04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235', '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd').to_hex).to eq('512103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea23552ae')
      expect(sh(multi(2, "[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc", "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0")).to_hex).to eq('a91445a9a622a8b0a1269944be477640eedc447bbd8487')
      expect(sh(multi(2, "[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL", "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0")).to_hex).to eq('a91445a9a622a8b0a1269944be477640eedc447bbd8487')
      expect(sortedmulti(2, "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/0", "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0/0/0").to_hex).to eq("5221025d5fc65ebb8d44a5274b53bac21ff8307fec2334a32df05553459f8b1f7fe1b62102fbd47cc8034098f0e6a94c6aeee8528abf0a2153a5d8e46d325b7284c046784652ae")
      expect(sortedmulti(2, "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1", "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0/0/1").to_hex).to eq("52210264fd4d1f5dea8ded94c61e9641309349b62f27fbffe807291f664e286bfbe6472103f4ece6dfccfa37b211eb3d0af4d0c61dba9ef698622dc17eecdf764beeb005a652ae")
      expect(sortedmulti(2, "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/2", "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0/0/2").to_hex).to eq("5221022ccabda84c30bad578b13c89eb3b9544ce149787e5b538175b1d1ba259cbb83321024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c52ae")
      expect(wsh(multi(2,
                       "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0",
                       "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/0",
                       "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/0'")).to_hex).
        to eq("0020b92623201f3bb7c3771d45b2ad1d0351ea8fbf8cfe0a0e570264e1075fa1948f")
      expect(sh(wsh(multi(16,
                          "KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy",
                          "KwGNz6YCCQtYvFzMtrC6D3tKTKdBBboMrLTsjr2NYVBwapCkn7Mr",
                          "KxogYhiNfwxuswvXV66eFyKcCpm7dZ7TqHVqujHAVUjJxyivxQ9X",
                          "L2BUNduTSyZwZjwNHynQTF14mv2uz2NRq5n5sYWTb4FkkmqgEE9f",
                          "L1okJGHGn1kFjdXHKxXjwVVtmCMR2JA5QsbKCSpSb7ReQjezKeoD",
                          "KxDCNSST75HFPaW5QKpzHtAyaCQC7p9Vo3FYfi2u4dXD1vgMiboK",
                          "L5edQjFtnkcf5UWURn6UuuoFrabgDQUHdheKCziwN42aLwS3KizU",
                          "KzF8UWFcEC7BYTq8Go1xVimMkDmyNYVmXV5PV7RuDicvAocoPB8i",
                          "L3nHUboKG2w4VSJ5jYZ5CBM97oeK6YuKvfZxrefdShECcjEYKMWZ",
                          "KyjHo36dWkYhimKmVVmQTq3gERv3pnqA4xFCpvUgbGDJad7eS8WE",
                          "KwsfyHKRUTZPQtysN7M3tZ4GXTnuov5XRgjdF2XCG8faAPmFruRF",
                          "KzCUbGhN9LJhdeFfL9zQgTJMjqxdBKEekRGZX24hXdgCNCijkkap",
                          "KzgpMBwwsDLwkaC5UrmBgCYaBD2WgZ7PBoGYXR8KT7gCA9UTN5a3",
                          "KyBXTPy4T7YG4q9tcAM3LkvfRpD1ybHMvcJ2ehaWXaSqeGUxEdkP",
                          "KzJDe9iwJRPtKP2F2AoN6zBgzS7uiuAwhWCfGdNeYJ3PC1HNJ8M8",
                          "L1xbHrxynrqLKkoYc4qtoQPx6uy5qYXR5ZDYVYBSRmCV5piU3JG9"
                          ))).to_hex).to eq("a9147fc63e13dc25e8a95a3cee3d9a714ac3afd96f1e87")

      # Invalid case
      keys = %w(KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy KwGNz6YCCQtYvFzMtrC6D3tKTKdBBboMrLTsjr2NYVBwapCkn7Mr KxogYhiNfwxuswvXV66eFyKcCpm7dZ7TqHVqujHAVUjJxyivxQ9X L2BUNduTSyZwZjwNHynQTF14mv2uz2NRq5n5sYWTb4FkkmqgEE9f L1okJGHGn1kFjdXHKxXjwVVtmCMR2JA5QsbKCSpSb7ReQjezKeoD KxDCNSST75HFPaW5QKpzHtAyaCQC7p9Vo3FYfi2u4dXD1vgMiboK L5edQjFtnkcf5UWURn6UuuoFrabgDQUHdheKCziwN42aLwS3KizU KzF8UWFcEC7BYTq8Go1xVimMkDmyNYVmXV5PV7RuDicvAocoPB8i L3nHUboKG2w4VSJ5jYZ5CBM97oeK6YuKvfZxrefdShECcjEYKMWZ KyjHo36dWkYhimKmVVmQTq3gERv3pnqA4xFCpvUgbGDJad7eS8WE KwsfyHKRUTZPQtysN7M3tZ4GXTnuov5XRgjdF2XCG8faAPmFruRF KzCUbGhN9LJhdeFfL9zQgTJMjqxdBKEekRGZX24hXdgCNCijkkap KzgpMBwwsDLwkaC5UrmBgCYaBD2WgZ7PBoGYXR8KT7gCA9UTN5a3 KyBXTPy4T7YG4q9tcAM3LkvfRpD1ybHMvcJ2ehaWXaSqeGUxEdkP KzJDe9iwJRPtKP2F2AoN6zBgzS7uiuAwhWCfGdNeYJ3PC1HNJ8M8 L1xbHrxynrqLKkoYc4qtoQPx6uy5qYXR5ZDYVYBSRmCV5piU3JG9)
      expect{sh(multi(16, *keys))}.to raise_error(ArgumentError, 'P2SH script is too large, 547 bytes is larger than 520 bytes.')
      keys = %w(03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0 0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600 0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8 0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8 02da72e8b46901a65d4374fe6315538d8f368557dda3a1dcf9ea903f3afe7314c8 0318c82dd0b53fd3a932d16e0ba9e278fcc937c582d5781be626ff16e201f72286 0297ccef1ef99f9d73dec9ad37476ddb232f1238aff877af19e72ba04493361009 02e502cfd5c3f972fe9a3e2a18827820638f96b6f347e54d63deb839011fd5765d 03e687710f0e3ebe81c1037074da939d409c0025f17eb86adb9427d28f0f7ae0e9 02c04d3a5274952acdbc76987f3184b346a483d43be40874624b29e3692c1df5af 02ed06e0f418b5b43a7ec01d1d7d27290fa15f75771cb69b642a51471c29c84acd 036d46073cbb9ffee90473f3da429abc8de7f8751199da44485682a989a4bebb24 02f5d1ff7c9029a80a4e36b9a5497027ef7f3e73384a4a94fbfe7c4e9164eec8bc 02e41deffd1b7cce11cde209a781adcffdabd1b91c0ba0375857a2bfd9302419f3 02d76625f7956a7fc505ab02556c23ee72d832f1bac391bcd2d3abce5710a13d06 0399eb0a5487515802dc14544cf10b3666623762fbed2ec38a3975716e2c29c232)
      expect{sh(multi(16, *keys))}.to raise_error(ArgumentError, 'P2SH script is too large, 547 bytes is larger than 520 bytes.')
      expect{wsh(multi(2,
                       "[aaaaaaaa][aaaaaaaa]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0",
                       "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*",
                       "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'"))}.
        to raise_error(ArgumentError, "Multiple ']' characters found for a single pubkey.")
      expect{wsh(multi(2,
                       "[aaaaaaaa][aaaaaaaa]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0",
                       "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*",
                       "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'"))}.
        to raise_error(ArgumentError, "Multiple ']' characters found for a single pubkey.")
      expect{wsh(multi(2,
                       "[aaaagaaa]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0",
                       "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*",
                       "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'"))}.
        to raise_error(ArgumentError, "Fingerprint 'aaaagaaa' is not hex.")
      expect{wsh(multi(2,
                       "[aaagaaaa]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0",
                       "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*",
                       "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'"))}.
        to raise_error(ArgumentError, "Fingerprint 'aaagaaaa' is not hex.")
      expect{wsh(multi(2,
                       "[aaaaaaaa]",
                       "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/0",
                       "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/0'"
                       ))}.
        to raise_error(ArgumentError, "No key provided.")
      expect{wsh(multi(2,
                       "[aaaaaaaa]",
                       "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/1",
                       "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/1h"
                 ))}.
        to raise_error(ArgumentError, "No key provided.")
      # Too short fingerprint
      expect{wsh(multi(2,
                       "[aaaaaaa]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0",
                       "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*",
                       "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'"))}.
        to raise_error(ArgumentError, "Fingerprint 'aaaaaaa' is not 4 bytes.")
      expect{wsh(multi(2,
                       "[aaaaaaa]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0",
                       "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*",
                       "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'"))}.
        to raise_error(ArgumentError, "Fingerprint 'aaaaaaa' is not 4 bytes.")
      # Too long fingerprint
      expect{wsh(multi(2,
                       "[aaaaaaaaa]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0",
                       "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*",
                       "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'"))}.
        to raise_error(ArgumentError, "Fingerprint 'aaaaaaaaa' is not 4 bytes.")
      expect{wsh(multi(2,
                       "[aaaaaaaaa]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0",
                       "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*",
                       "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'"))}.
        to raise_error(ArgumentError, "Fingerprint 'aaaaaaaaa' is not 4 bytes.")
      expect{multi("a", "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss")}.
        to raise_error(ArgumentError, "Multisig threshold 'a' is not valid.")
      expect{multi("a",
                   "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd",
                   "04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235")}.
        to raise_error(ArgumentError, "Multisig threshold 'a' is not valid.")
      expect{multi(0, "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1", "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss")}.
        to raise_error(ArgumentError, "Multisig threshold cannot be 0, must be at least 1.")
      expect{multi(0,
                   "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd",
                   "04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235")}.
        to raise_error(ArgumentError, "Multisig threshold cannot be 0, must be at least 1.")
      expect{multi(3, "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1", "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss")}.
        to raise_error(ArgumentError, "Multisig threshold cannot be larger than the number of keys.")
      expect{multi(3,
                   "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd",
                   "04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235")}.
        to raise_error(ArgumentError, "Multisig threshold cannot be larger than the number of keys.")
      expect{multi(3,
                   "KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy",
                   "KwGNz6YCCQtYvFzMtrC6D3tKTKdBBboMrLTsjr2NYVBwapCkn7Mr",
                   "KxogYhiNfwxuswvXV66eFyKcCpm7dZ7TqHVqujHAVUjJxyivxQ9X",
                   "L2BUNduTSyZwZjwNHynQTF14mv2uz2NRq5n5sYWTb4FkkmqgEE9f").to_hex}.
        to raise_error(RuntimeError, "Cannot have 4 pubkeys in bare multisig; only at most 3 pubkeys.")
      expect{multi(3,
                   "03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0",
                   "0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600",
                   "0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8",
                   "0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8").to_hex}.
        to raise_error(RuntimeError, "Cannot have 4 pubkeys in bare multisig; only at most 3 pubkeys.")

      # Cannot have more than 15 keys in a P2SH multisig, or we exceed maximum push size
      keys = %w(KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy KwGNz6YCCQtYvFzMtrC6D3tKTKdBBboMrLTsjr2NYVBwapCkn7Mr KxogYhiNfwxuswvXV66eFyKcCpm7dZ7TqHVqujHAVUjJxyivxQ9X L2BUNduTSyZwZjwNHynQTF14mv2uz2NRq5n5sYWTb4FkkmqgEE9f L1okJGHGn1kFjdXHKxXjwVVtmCMR2JA5QsbKCSpSb7ReQjezKeoD KxDCNSST75HFPaW5QKpzHtAyaCQC7p9Vo3FYfi2u4dXD1vgMiboK L5edQjFtnkcf5UWURn6UuuoFrabgDQUHdheKCziwN42aLwS3KizU KzF8UWFcEC7BYTq8Go1xVimMkDmyNYVmXV5PV7RuDicvAocoPB8i L3nHUboKG2w4VSJ5jYZ5CBM97oeK6YuKvfZxrefdShECcjEYKMWZ KyjHo36dWkYhimKmVVmQTq3gERv3pnqA4xFCpvUgbGDJad7eS8WE KwsfyHKRUTZPQtysN7M3tZ4GXTnuov5XRgjdF2XCG8faAPmFruRF KzCUbGhN9LJhdeFfL9zQgTJMjqxdBKEekRGZX24hXdgCNCijkkap KzgpMBwwsDLwkaC5UrmBgCYaBD2WgZ7PBoGYXR8KT7gCA9UTN5a3 KyBXTPy4T7YG4q9tcAM3LkvfRpD1ybHMvcJ2ehaWXaSqeGUxEdkP KzJDe9iwJRPtKP2F2AoN6zBgzS7uiuAwhWCfGdNeYJ3PC1HNJ8M8 L1xbHrxynrqLKkoYc4qtoQPx6uy5qYXR5ZDYVYBSRmCV5piU3JG9 L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)
      expect{sh(multi(16, *keys))}.to raise_error(ArgumentError, "P2SH script is too large, 582 bytes is larger than 520 bytes.")
      keys = %w(03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0 0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600 0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8 0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8 02da72e8b46901a65d4374fe6315538d8f368557dda3a1dcf9ea903f3afe7314c8 0318c82dd0b53fd3a932d16e0ba9e278fcc937c582d5781be626ff16e201f72286 0297ccef1ef99f9d73dec9ad37476ddb232f1238aff877af19e72ba04493361009 02e502cfd5c3f972fe9a3e2a18827820638f96b6f347e54d63deb839011fd5765d 03e687710f0e3ebe81c1037074da939d409c0025f17eb86adb9427d28f0f7ae0e9 02c04d3a5274952acdbc76987f3184b346a483d43be40874624b29e3692c1df5af 02ed06e0f418b5b43a7ec01d1d7d27290fa15f75771cb69b642a51471c29c84acd 036d46073cbb9ffee90473f3da429abc8de7f8751199da44485682a989a4bebb24 02f5d1ff7c9029a80a4e36b9a5497027ef7f3e73384a4a94fbfe7c4e9164eec8bc 02e41deffd1b7cce11cde209a781adcffdabd1b91c0ba0375857a2bfd9302419f3 02d76625f7956a7fc505ab02556c23ee72d832f1bac391bcd2d3abce5710a13d06 0399eb0a5487515802dc14544cf10b3666623762fbed2ec38a3975716e2c29c232 03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)
      expect{sh(multi(16, *keys))}.to raise_error(ArgumentError, "P2SH script is too large, 582 bytes is larger than 520 bytes.")

      # In P2WSH we can have up to 20 keys
      keys = %w(KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy KwGNz6YCCQtYvFzMtrC6D3tKTKdBBboMrLTsjr2NYVBwapCkn7Mr KxogYhiNfwxuswvXV66eFyKcCpm7dZ7TqHVqujHAVUjJxyivxQ9X L2BUNduTSyZwZjwNHynQTF14mv2uz2NRq5n5sYWTb4FkkmqgEE9f L1okJGHGn1kFjdXHKxXjwVVtmCMR2JA5QsbKCSpSb7ReQjezKeoD KxDCNSST75HFPaW5QKpzHtAyaCQC7p9Vo3FYfi2u4dXD1vgMiboK L5edQjFtnkcf5UWURn6UuuoFrabgDQUHdheKCziwN42aLwS3KizU KzF8UWFcEC7BYTq8Go1xVimMkDmyNYVmXV5PV7RuDicvAocoPB8i L3nHUboKG2w4VSJ5jYZ5CBM97oeK6YuKvfZxrefdShECcjEYKMWZ KyjHo36dWkYhimKmVVmQTq3gERv3pnqA4xFCpvUgbGDJad7eS8WE KwsfyHKRUTZPQtysN7M3tZ4GXTnuov5XRgjdF2XCG8faAPmFruRF KzCUbGhN9LJhdeFfL9zQgTJMjqxdBKEekRGZX24hXdgCNCijkkap KzgpMBwwsDLwkaC5UrmBgCYaBD2WgZ7PBoGYXR8KT7gCA9UTN5a3 KyBXTPy4T7YG4q9tcAM3LkvfRpD1ybHMvcJ2ehaWXaSqeGUxEdkP KzJDe9iwJRPtKP2F2AoN6zBgzS7uiuAwhWCfGdNeYJ3PC1HNJ8M8 L1xbHrxynrqLKkoYc4qtoQPx6uy5qYXR5ZDYVYBSRmCV5piU3JG9 KzRedjSwMggebB3VufhbzpYJnvHfHe9kPJSjCU5QpJdAW3NSZxYS Kyjtp5858xL7JfeV4PNRCKy2t6XvgqNNepArGY9F9F1SSPqNEMs3 L2D4RLHPiHBidkHS8ftx11jJk1hGFELvxh8LoxNQheaGT58dKenW KyLPZdwY4td98bKkXqEXTEBX3vwEYTQo1yyLjX2jKXA63GBpmSjv)
      expect(wsh(multi(20, *keys)).to_hex).to eq('0020376bd8344b8b6ebe504ff85ef743eaa1aa9272178223bcb6887e9378efb341ac')
      # Even if it's wrapped into P2SH
      expect(sh(wsh(multi(20, *keys))).to_hex).to eq('a914c2c9c510e9d7f92fd6131e94803a8d34a8ef675e87')
      keys = %w(03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0 0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600 0362a74e399c39ed5593852a30147f2959b56bb827dfa3e60e464b02ccf87dc5e8 0261345b53de74a4d721ef877c255429961b7e43714171ac06168d7e08c542a8b8 02da72e8b46901a65d4374fe6315538d8f368557dda3a1dcf9ea903f3afe7314c8 0318c82dd0b53fd3a932d16e0ba9e278fcc937c582d5781be626ff16e201f72286 0297ccef1ef99f9d73dec9ad37476ddb232f1238aff877af19e72ba04493361009 02e502cfd5c3f972fe9a3e2a18827820638f96b6f347e54d63deb839011fd5765d 03e687710f0e3ebe81c1037074da939d409c0025f17eb86adb9427d28f0f7ae0e9 02c04d3a5274952acdbc76987f3184b346a483d43be40874624b29e3692c1df5af 02ed06e0f418b5b43a7ec01d1d7d27290fa15f75771cb69b642a51471c29c84acd 036d46073cbb9ffee90473f3da429abc8de7f8751199da44485682a989a4bebb24 02f5d1ff7c9029a80a4e36b9a5497027ef7f3e73384a4a94fbfe7c4e9164eec8bc 02e41deffd1b7cce11cde209a781adcffdabd1b91c0ba0375857a2bfd9302419f3 02d76625f7956a7fc505ab02556c23ee72d832f1bac391bcd2d3abce5710a13d06 0399eb0a5487515802dc14544cf10b3666623762fbed2ec38a3975716e2c29c232 02bc2feaa536991d269aae46abb8f3772a5b3ad592314945e51543e7da84c4af6e 0318bf32e5217c1eb771a6d5ce1cd39395dff7ff665704f175c9a5451d95a2f2ca 02c681a6243f16208c2004bb81f5a8a67edfdd3e3711534eadeec3dcf0b010c759 0249fdd6b69768b8d84b4893f8ff84b36835c50183de20fcae8f366a45290d01fd)
      expect(wsh(multi(20, *keys)).to_hex).to eq('0020376bd8344b8b6ebe504ff85ef743eaa1aa9272178223bcb6887e9378efb341ac')
      expect(sh(wsh(multi(20, *keys))).to_hex).to eq('a914c2c9c510e9d7f92fd6131e94803a8d34a8ef675e87')

      # Check for invalid nesting of structures
      expect{sh('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')}.to raise_error(ArgumentError, 'A function is needed within P2SH.')
      expect{sh(combo('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1'))}.to raise_error(ArgumentError, 'Can only have combo() at top level.')
      expect{wsh('03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd')}.to raise_error(ArgumentError, 'A function is needed within P2WSH.')
      expect{wsh(wpkh('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1'))}.to raise_error(ArgumentError, 'Can only have wpkh() at top level or inside sh().')
      expect{wsh(sh(pk('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')))}.to raise_error(ArgumentError, 'Can only have sh() at top level.')
      expect{sh(sh(pk('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')))}.to raise_error(ArgumentError, 'Can only have sh() at top level.')
      expect{wsh(wsh(pk('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')))}.to raise_error(ArgumentError, 'Can only have wsh() at top level or inside sh().')
      expect{combo(pkh('03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd'))}.to raise_error(ArgumentError, 'Key must be string.') # BIP-384

      # Checksums
      expected = 'a91445a9a622a8b0a1269944be477640eedc447bbd8487'
      base = "sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))"
      expect(described_class.parse("#{base}#ggrsrxfy").to_hex).to eq(expected)
      expect(Bitcoin::Descriptor::Checksum.descsum_check("#{base}#ggrsrxfy")).to be true
      expect(described_class.parse("#{base}#ggrsrxfy").to_s(checksum: true)).to eq("#{base}#ggrsrxfy")
      expect(described_class.parse("sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5t").to_hex).to eq(expected)
      expect(described_class.parse("#{base}").to_hex).to eq(expected)
      expect(described_class.parse("sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))").to_hex).to eq(expected)
      expect{described_class.parse("#{base}#")}.to raise_error(ArgumentError, "Expected 8 character checksum, not 0 characters.")
      expect{described_class.parse("#{base}#ggrsrxfyq")}.to raise_error(ArgumentError, "Expected 8 character checksum, not 9 characters.")
      expect{described_class.parse("#{base}#ggrsrxf")}.to raise_error(ArgumentError, "Expected 8 character checksum, not 7 characters.")
      expect{described_class.parse("sh(multi(3,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5t")}.
        to raise_error(ArgumentError, "Provided checksum 'tjg09x5t' does not match computed checksum 'd4x0uxyv'.")
      expect{described_class.parse("sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjq09x4t")}.
        to raise_error(ArgumentError, "Provided checksum 'tjq09x4t' does not match computed checksum 'tjg09x5t'.")
      expect{described_class.parse("#{base}##ggssrxfy")}.to raise_error(ArgumentError, "Multiple '#' symbols.")
    end
  end

  describe 'expression#to_s and #parse' do
    it do
      combo = combo('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')
      expect(combo.to_s).to eq("combo(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)")
      expect(described_class.parse("combo(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)")).to eq(combo)
      pk = pk("L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1")
      expect(pk.to_s).to eq("pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)")
      expect(described_class.parse(pk.to_s)).to eq(pk)
      pk = pk("03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd")
      expect(pk.to_s).to eq("pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)")
      pkh = pkh("[deadbeef/1/2'/3/4']L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1")
      expect(pkh.to_s).to eq("pkh([deadbeef/1/2'/3/4']L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)")
      expect(described_class.parse(pkh.to_s)).to eq(pkh)
      wpkh = wpkh('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')
      expect(wpkh.to_s).to eq("wpkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)")
      expect(described_class.parse(wpkh.to_s)).to eq(wpkh)
      sh = sh(pk('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1'))
      expect(sh.to_s).to eq("sh(pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))")
      expect(described_class.parse(sh.to_s)).to eq(sh)
      wsh = wsh(pkh('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1'))
      expect(wsh.to_s).to eq("wsh(pkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1))")
      expect(described_class.parse(wsh.to_s)).to eq(wsh)
      multi = multi(1, '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd', '04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235')
      expect(multi.to_s).to eq("multi(1,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)")
      expect(described_class.parse(multi.to_s)).to eq(multi)
      sorted_multi = sortedmulti(1, 'L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1', '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss')
      expect(sorted_multi.to_s).to eq("sortedmulti(1,L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1,5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss)")
      expect(described_class.parse(sorted_multi.to_s)).to eq(sorted_multi)
      nested_multi = sh(wsh(multi(16,
                                  "KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy",
                                  "KwGNz6YCCQtYvFzMtrC6D3tKTKdBBboMrLTsjr2NYVBwapCkn7Mr",
                                  "KxogYhiNfwxuswvXV66eFyKcCpm7dZ7TqHVqujHAVUjJxyivxQ9X",
                                  "L2BUNduTSyZwZjwNHynQTF14mv2uz2NRq5n5sYWTb4FkkmqgEE9f",
                                  "L1okJGHGn1kFjdXHKxXjwVVtmCMR2JA5QsbKCSpSb7ReQjezKeoD",
                                  "KxDCNSST75HFPaW5QKpzHtAyaCQC7p9Vo3FYfi2u4dXD1vgMiboK",
                                  "L5edQjFtnkcf5UWURn6UuuoFrabgDQUHdheKCziwN42aLwS3KizU",
                                  "KzF8UWFcEC7BYTq8Go1xVimMkDmyNYVmXV5PV7RuDicvAocoPB8i",
                                  "L3nHUboKG2w4VSJ5jYZ5CBM97oeK6YuKvfZxrefdShECcjEYKMWZ",
                                  "KyjHo36dWkYhimKmVVmQTq3gERv3pnqA4xFCpvUgbGDJad7eS8WE",
                                  "KwsfyHKRUTZPQtysN7M3tZ4GXTnuov5XRgjdF2XCG8faAPmFruRF",
                                  "KzCUbGhN9LJhdeFfL9zQgTJMjqxdBKEekRGZX24hXdgCNCijkkap",
                                  "KzgpMBwwsDLwkaC5UrmBgCYaBD2WgZ7PBoGYXR8KT7gCA9UTN5a3",
                                  "KyBXTPy4T7YG4q9tcAM3LkvfRpD1ybHMvcJ2ehaWXaSqeGUxEdkP",
                                  "KzJDe9iwJRPtKP2F2AoN6zBgzS7uiuAwhWCfGdNeYJ3PC1HNJ8M8",
                                  "L1xbHrxynrqLKkoYc4qtoQPx6uy5qYXR5ZDYVYBSRmCV5piU3JG9"
                            )))
      expect(nested_multi.to_s).to eq("sh(wsh(multi(16,KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy,KwGNz6YCCQtYvFzMtrC6D3tKTKdBBboMrLTsjr2NYVBwapCkn7Mr,KxogYhiNfwxuswvXV66eFyKcCpm7dZ7TqHVqujHAVUjJxyivxQ9X,L2BUNduTSyZwZjwNHynQTF14mv2uz2NRq5n5sYWTb4FkkmqgEE9f,L1okJGHGn1kFjdXHKxXjwVVtmCMR2JA5QsbKCSpSb7ReQjezKeoD,KxDCNSST75HFPaW5QKpzHtAyaCQC7p9Vo3FYfi2u4dXD1vgMiboK,L5edQjFtnkcf5UWURn6UuuoFrabgDQUHdheKCziwN42aLwS3KizU,KzF8UWFcEC7BYTq8Go1xVimMkDmyNYVmXV5PV7RuDicvAocoPB8i,L3nHUboKG2w4VSJ5jYZ5CBM97oeK6YuKvfZxrefdShECcjEYKMWZ,KyjHo36dWkYhimKmVVmQTq3gERv3pnqA4xFCpvUgbGDJad7eS8WE,KwsfyHKRUTZPQtysN7M3tZ4GXTnuov5XRgjdF2XCG8faAPmFruRF,KzCUbGhN9LJhdeFfL9zQgTJMjqxdBKEekRGZX24hXdgCNCijkkap,KzgpMBwwsDLwkaC5UrmBgCYaBD2WgZ7PBoGYXR8KT7gCA9UTN5a3,KyBXTPy4T7YG4q9tcAM3LkvfRpD1ybHMvcJ2ehaWXaSqeGUxEdkP,KzJDe9iwJRPtKP2F2AoN6zBgzS7uiuAwhWCfGdNeYJ3PC1HNJ8M8,L1xbHrxynrqLKkoYc4qtoQPx6uy5qYXR5ZDYVYBSRmCV5piU3JG9)))")
      expect(described_class.parse(nested_multi.to_s)).to eq(nested_multi)
    end
  end

  describe 'checksum' do
    it do
      desc_wpkh = "wpkh([00aabbcc/0]033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a)#g6gm8u7v"
      expect(described_class.parse(desc_wpkh).to_s(checksum: true)).to eq(desc_wpkh)
      desc_wsh = "wsh(pkh([00aabbcc/2]033d65a099daf8d973422e75f78c29504e5e53bfb81f3b08d9bb161cdfb3c3ee9a))#nue4wg6d"
      expect(described_class.parse(desc_wsh).to_s(checksum: true)).to eq(desc_wsh)
      desc_multi = "multi(1,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)"
      expect(described_class.parse(desc_multi).to_s(checksum: true)).to eq("#{desc_multi}#evpem6ml")
      desc_combo = 'combo(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)'
      expect(described_class.parse(desc_combo).to_s(checksum: true)).to eq("#{desc_combo}#p5326pcv")
    end
  end

  describe "BIP-385" do
    it do
      desc_raw = 'raw(deadbeef)'
      raw = described_class.parse(desc_raw)
      expect(raw.to_hex).to eq("deadbeef")
      expect(raw("deadbeef")).to eq(raw)
      expect(raw.to_s(checksum: true)).to eq("#{desc_raw}#89f8spxm")

      expect{raw('asdf')}.to raise_error(ArgumentError, "Raw script is not hex.")
      expect{sh(raw('deadbeef'))}.to raise_error(ArgumentError, "Can only have raw() at top level.")
      expect{wsh(raw('deadbeef'))}.to raise_error(ArgumentError, "Can only have raw() at top level.")

      p2sh = "3PUNyaW7M55oKWJ3kDukwk9bsKvryra15j"
      desc_addr = "addr(#{p2sh})"
      addr = described_class.parse(desc_addr)
      expect(addr.to_hex).to eq("a914eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee87")
      expect(addr('3PUNyaW7M55oKWJ3kDukwk9bsKvryra15j')).to eq(addr)
      expect(addr.to_s(checksum: true)).to eq("#{desc_addr}#6vhk2xgr")

      expect{addr('asdf')}.to raise_error(ArgumentError, "Address is not valid.")
      expect{sh(addr(p2sh))}.to raise_error(ArgumentError, "Can only have addr() at top level.")
      expect{wsh(addr(p2sh))}.to raise_error(ArgumentError, "Can only have addr() at top level.")
    end
  end

  describe "BIP-386" do
    it do
      key = 'a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd'
      desc_tr = "tr(#{key})"
      tr = described_class.parse(desc_tr)
      expected = '512077aab6e066f8a7419c5ab714c12c67d25007ed55a43cadcacb4d7a970a093f11'
      expect(tr.to_hex).to eq(expected)
      expect(tr(key)).to eq(tr)
      expect(tr.to_s).to eq(desc_tr)
      expect(tr.to_s(checksum: true)).to eq("#{desc_tr}#dh4fyxrd")
      expect(tr('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1').to_hex).to eq(expected)
      expect(tr('xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/0/0',
                pk('xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/1/0')).to_hex).
        to eq('512078bc707124daa551b65af74de2ec128b7525e10f374dc67b64e00ce0ab8b3e12')

      expect(tr(key, pk('669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0')).to_hex).
        to eq('512017cf18db381d836d8923b1bdb246cfcd818da1a9f0e6e7907f187f0b2f937754')
      expect(tr(key, [
        pk('xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334/0'),
        [
          [
            pk('xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL'),
            pk('02df12b7035bdac8e3bab862a3a83d06ea6b17b6753d52edecba9be46f5d09e076')
          ],
          pk('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')
        ]
      ]).to_hex).to eq('512071fff39599a7b78bc02623cbe814efebf1a404f5d8ad34ea80f213bd8943f574')
      desc_tr = "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{pk(xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334/0),{{pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL),pk(02df12b7035bdac8e3bab862a3a83d06ea6b17b6753d52edecba9be46f5d09e076)},pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)}})"
      tr = described_class.parse(desc_tr)
      expect(tr.to_hex).to eq('512071fff39599a7b78bc02623cbe814efebf1a404f5d8ad34ea80f213bd8943f574')
      expect(tr.to_s).to eq(desc_tr)

      expect{tr('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss')}.to raise_error(ArgumentError, "Uncompressed key are not allowed.")
      expect{tr('04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235')}.
        to raise_error(ArgumentError, "Uncompressed key are not allowed.")
      expect{wsh(tr(key))}.
        to raise_error(ArgumentError, "Can only have tr() at top level.")
      expect{sh(tr(key))}.
        to raise_error(ArgumentError, "Can only have tr() at top level.")
    end
  end

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
      multi_a = described_class.parse(desc_multi_a)
      expect(multi_a.to_hex).to eq('5120e4c8f2b0a7d3a688ac131cb03248c0d4b0a59bbd4f37211c848cfbd22a981192')
      expect(multi_a.to_s).to eq(desc_multi_a)

      key = '03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0'
      expect{multi_a(1, key).to_hex}.
        to raise_error(RuntimeError, 'Can only have multi_a/sortedmulti_a inside tr().')
      expect{described_class.parse("multi_a(1,#{key})")}.
        to raise_error(ArgumentError, 'Can only have multi_a/sortedmulti_a inside tr().')
      expect{sortedmulti_a(1, key).to_hex}.
        to raise_error(RuntimeError, 'Can only have multi_a/sortedmulti_a inside tr().')
      expect{described_class.parse("sortedmulti_a(1,#{key})")}.
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
