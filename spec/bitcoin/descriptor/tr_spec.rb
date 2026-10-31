require 'spec_helper'

RSpec.describe Bitcoin::Descriptor::Tr, network: :mainnet do

  include Bitcoin::Descriptor

  describe "BIP-386" do
    it do
      key = 'a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd'
      desc_tr = "tr(#{key})"
      tr = Bitcoin::Descriptor.parse(desc_tr)
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
      tr = Bitcoin::Descriptor.parse(desc_tr)
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

  describe 'tree validation' do
    let(:key) { 'a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd' }
    let(:compressed) { '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd' }
    let(:uncompressed) { '04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235' }
    let(:hybrid) { '06a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235' }

    it 'should accept pk(), multi_a() and sortedmulti_a() as leaves' do
      expect(Bitcoin::Descriptor.parse("tr(#{key},pk(#{compressed}))").to_hex).to be_a(String)
      expect(Bitcoin::Descriptor.parse("tr(#{key},multi_a(1,#{key},#{compressed}))").to_hex).to be_a(String)
      expect(Bitcoin::Descriptor.parse("tr(#{key},{pk(#{key}),sortedmulti_a(1,#{key},#{compressed})})").to_hex).to be_a(String)
    end

    it 'should reject an expression which is not a tapscript leaf' do
      {
        "multi(1,#{compressed})" => 'Can only have multi/sortedmulti at top level, in sh(), or in wsh().',
        "sortedmulti(1,#{compressed})" => 'Can only have multi/sortedmulti at top level, in sh(), or in wsh().',
        "wpkh(#{compressed})" => 'Can only have wpkh() at top level or inside sh().',
        "sh(pk(#{compressed}))" => 'Can only have sh() at top level.',
        "wsh(pk(#{compressed}))" => 'Can only have wsh() at top level or inside sh().',
        "addr(1BitcoinEaterAddressDontSendf59kuE)" => 'Can only have addr() at top level.',
        "combo(#{compressed})" => 'Can only have combo() at top level.',
        "raw(51)" => 'Can only have raw() at top level.',
        "tr(#{key})" => 'Can only have tr() at top level.',
        "rawtr(#{key})" => 'Can only have rawtr() at top level.',
        "pkh(#{compressed})" => 'pkh() is not allowed in a tr() tree.'
      }.each do |leaf, message|
        expect { Bitcoin::Descriptor.parse("tr(#{key},#{leaf})") }.to raise_error(ArgumentError, message), leaf
        expect { Bitcoin::Descriptor.parse("tr(#{key},{pk(#{key}),#{leaf}})") }.to raise_error(ArgumentError, message), leaf
      end
      expect { tr(key, [pk(key), wpkh(compressed)]) }.to raise_error(ArgumentError, 'Can only have wpkh() at top level or inside sh().')
    end

    it 'should reject an uncompressed or hybrid key in a leaf' do
      expect { Bitcoin::Descriptor.parse("tr(#{key},pk(#{uncompressed}))") }.to raise_error(ArgumentError, 'Uncompressed key are not allowed.')
      expect { Bitcoin::Descriptor.parse("tr(#{key},multi_a(1,#{key},#{uncompressed}))") }.to raise_error(ArgumentError, 'Uncompressed key are not allowed.')
      expect { Bitcoin::Descriptor.parse("tr(#{key},{pk(#{key}),{pk(#{key}),pk(#{uncompressed})}})") }.to raise_error(ArgumentError, 'Uncompressed key are not allowed.')
      # A hybrid key is rejected as a public key before the compression is looked at.
      expect { Bitcoin::Descriptor.parse("tr(#{key},pk(#{hybrid}))") }.to raise_error(ArgumentError, 'Invalid public key.')
    end

    it 'should keep the commas of a leaf expression inside braces' do
      desc = "tr(#{key},{multi_a(1,#{key},#{compressed}),{pk(#{key}),sortedmulti_a(2,#{compressed},#{key})}})"
      tr = Bitcoin::Descriptor.parse(desc)
      expect(tr.tree[0].type).to eq(:multi_a)
      expect(tr.tree[0].keys.size).to eq(2)
      expect(tr.tree[1][1].type).to eq(:sortedmulti_a)
      expect(tr.to_s).to eq(desc)
    end
  end
end