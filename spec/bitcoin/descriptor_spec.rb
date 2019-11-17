require 'spec_helper'

describe Bitcoin::Descriptor, network: :mainnet do

  include Bitcoin::Descriptor

  describe 'Test Vector' do
    it 'should be passe' do
      # Basic single-key compressed
      combo = %w(2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac 76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac 00149a1c78a507689f6f54b847ad1cef1e614ee23f1e a91484ab21b1b2fd065d4504ff693d832434b6108d7b87)
      expect(combo('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1').map(&:to_hex)).to eq(combo)
      expect(combo('03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd').map(&:to_hex)).to eq(combo)
      expect(pk("L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1").to_hex).to eq('2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac')
      expect(pk("03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd").to_hex).to eq('2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac')
      expect(pkh("[deadbeef/1/2'/3/4']L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1").to_hex).to eq('76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac')
      expect(sh(wpkh('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1')).to_hex).to eq('a91484ab21b1b2fd065d4504ff693d832434b6108d7b87')
      expect{sh(wpkh('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY2'))}.to raise_error(ArgumentError, 'Invalid pubkey.')
      expect{pkh("deadbeef/1/2'/3/4']L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1")}.to raise_error(ArgumentError, 'Invalid key origin.')
      expect{pkh("[deadbeef]/1/2'/3/4']L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1")}.to raise_error(ArgumentError, 'Invalid key origin.')

      # Basic single-key uncompressed
      combo = %w(4104a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235ac 76a914b5bd079c4d57cc7fc28ecf8213a6b791625b818388ac)
      expect(combo('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss').map(&:to_hex)).to eq(combo)
      expect(combo('04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235').map(&:to_hex)).to eq(combo)
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
      expect(combo('[01234567]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc').map(&:to_hex)).to eq(combo)
      expect(combo('[01234567]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL').map(&:to_hex)).to eq(combo)
      expect(pk('xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0').to_hex).to eq('210379e45b3cf75f9c5f9befd8e9506fb962f6a9d185ac87001ec44a8d3df8d4a9e3ac')
      expect(pk('xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0').to_hex).to eq('210379e45b3cf75f9c5f9befd8e9506fb962f6a9d185ac87001ec44a8d3df8d4a9e3ac')
      expect(pkh("xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0").to_hex).to eq('76a914ebdc90806a9c4356c1c88e42216611e1cb4c1c1788ac')
      expect{combo("[012345678]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc")}.to raise_error(ArgumentError, 'Fingerprint is not 4 bytes.')
      expect{pkh("xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483648")}.to raise_error(ArgumentError, 'Key path value is out of range.')
      expect{pkh("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483648")}.to raise_error(ArgumentError, 'Key path value is out of range.')
      expect{pkh("xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/1aa")}.to raise_error(ArgumentError, 'Key path value is not a valid value.')
      expect{pkh("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1aa")}.to raise_error(ArgumentError, 'Key path value is not a valid value.')
    end
  end

  describe 'hoge' do
    it 'should' do
      expect{pkh("xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/1aa")}.to raise_error(ArgumentError, 'Key path value is not a valid value.')
    end
  end

end