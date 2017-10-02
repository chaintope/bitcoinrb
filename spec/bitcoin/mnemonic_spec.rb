require 'spec_helper'

describe Bitcoin::Mnemonic, network: :mainnet do

  subject { Bitcoin::Mnemonic.new('english') }

  describe '#initialize' do
    it 'should check supported words' do
      expect(subject.word_list).to eq('english')
      expect {Bitcoin::Mnemonic.new('english1')}.to raise_error(ArgumentError)
    end
  end

  describe '#languages' do
    it 'should be list support language' do
      expect(Bitcoin::Mnemonic.word_lists).to match_array(%w(english japanese french spanish chinese_simplified chinese_traditional italian))
    end
  end

  describe '#to_mnemonic' do
    it 'should be generate' do
      expect(subject.to_mnemonic('c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05')).to eq(%w(scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump))
    end
  end

  describe '#to_entropy' do
    it 'should be generate' do
      expect(subject.to_entropy(%w(scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump))).to eq('c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05')
    end
  end

  # https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#Test_vectors
  describe 'Test Vectors' do

    context 'english' do
      it 'pass test vectors' do
        vectors = fixture_file('vectors.json')['english']
        vectors.each do |entropy, mnemonic, seed, ext_priv_key|
          expect(subject.to_mnemonic(entropy)).to eq(mnemonic.split(' '))
          expect(subject.to_entropy(mnemonic.split(' '))).to eq(entropy)
          expect(subject.to_seed(mnemonic.split(' '), passphrase: 'TREZOR')).to eq(seed)
          xprv = Bitcoin::ExtKey.generate_master(subject.to_seed(mnemonic.split(' '), passphrase: 'TREZOR'))
          expect(xprv.to_base58).to eq(ext_priv_key)
        end
      end
    end

    context 'japanese' do
      subject { Bitcoin::Mnemonic.new('japanese') }
      it 'pass test vectors' do
        vectors = fixture_file('test_JP_BIP39.json')
        vectors.each do |vector|
          expect(subject.to_mnemonic(vector['entropy'])).to eq(vector['mnemonic'].split('　'))
          expect(subject.to_entropy(vector['mnemonic'].split('　'))).to eq(vector['entropy'])
          expect(subject.to_seed(vector['mnemonic'].split('　'), passphrase: vector['passphrase'])).to eq(vector['seed'])
          xprv = Bitcoin::ExtKey.generate_master(subject.to_seed(vector['mnemonic'].split('　'), passphrase: vector['passphrase']))
          expect(xprv.to_base58).to eq(vector['bip32_xprv'])
        end
      end
    end

  end

end
