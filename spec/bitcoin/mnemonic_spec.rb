require 'spec_helper'

describe Bitcoin::Mnemonic, network: :mainnet do

  subject { Bitcoin::Mnemonic.new('english') }

  describe '#initialize' do
    it 'should check supported words' do
      expect(subject.language).to eq('english')
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
    context 'lower case' do
      it 'should be generate' do
        expect(subject.to_entropy(%w(scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump))).to eq('c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05')
      end
    end

    context 'upper case' do
      it 'should be generate' do
        expect(subject.to_entropy(%w(SCISSORS INVITE LOCK MAPLE SUPREME RAW RAPID VOID CONGRESS MUSCLE DIGITAL ELEGANT LITTLE BRISK HAIR MANGO CONGRESS CLUMP))).to eq('c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05')
      end
    end

    context 'checksum mismatch' do
      it 'should raise error' do
        expect{subject.to_entropy(%w(letter advice cage absurd amount doctor acoustic avoid letter advice cage outside))}.to raise_error('checksum mismatch.')
      end
    end
  end

  describe '#to_seed' do
    context 'lower case' do
      it 'should be generate' do
        expect(subject.to_seed(%w(letter advice cage absurd amount doctor acoustic avoid letter advice cage above), passphrase: 'TREZOR')).to eq('d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8')
      end
    end

    context 'upper case' do
      it 'should be generate' do
        expect(subject.to_seed(%w(LETTER ADVICE CAGE ABSURD AMOUNT DOCTOR ACOUSTIC AVOID LETTER ADVICE CAGE ABOVE), passphrase: 'TREZOR')).to eq('d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8')
      end
    end

    context 'checksum mismatch' do
      it 'should raise error' do
        expect{subject.to_seed(%w(letter advice cage absurd amount doctor acoustic avoid letter advice cage outside))}.to raise_error('checksum mismatch.')
      end
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
