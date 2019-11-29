require 'spec_helper'

describe Bitcoin::SLIP39 do

  let(:master_secret) {'4142434445464748494a4b4c4d4e4f50'}  # 'ABCDEFGHIJKLMNOP'.unpack("H*").first
  let(:passphrase) {'TREZOR'}

  describe 'Test Vector' do
    vectors = fixture_file('slip39/vectors.json')
    vectors.each do |v|
      it "#{v[0]}" do
        if v[2].empty?
          expect{
            shares = v[1].map{|words|Bitcoin::SLIP39::Share.from_words(words.split(' '))}
            Bitcoin::SLIP39::SSS.recover_secret(shares, passphrase: 'TREZOR')
          }.to raise_error(ArgumentError)
        else
          shares = v[1].map{|words|Bitcoin::SLIP39::Share.from_words(words.split(' '))}
          expect(Bitcoin::SLIP39::SSS.recover_secret(shares, passphrase: 'TREZOR')).to eq(v[2])
          words = shares.map{|s|s.to_words.join(' ')}
          expect(words).to eq(v[1])
        end
      end
    end
  end

  describe 'basic sharing' do
    it 'should reconstruct same secret.' do
      group = Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 1, groups: [[3, 5]], secret: master_secret)
      expect(group.length).to eq(1)
      expect(group.first.length).to eq(5)
      s1 = Bitcoin::SLIP39::SSS.recover_secret(group.first[0..2])
      s2 = Bitcoin::SLIP39::SSS.recover_secret(group.first[2..-1])
      expect(s1).to eq(s2)
      expect(s1).to eq(master_secret)
    end
  end

  describe 'test passphrase' do
    it 'cannot be restored without a passphrase.' do
      shares = Bitcoin::SLIP39::SSS.setup_shares(group_threshold: 1, groups: [[3, 5]], secret: master_secret, passphrase: passphrase).first
      expect(Bitcoin::SLIP39::SSS.recover_secret(shares[1..3], passphrase: passphrase)).to eq(master_secret)
      expect(Bitcoin::SLIP39::SSS.recover_secret(shares[1..3])).not_to eq(master_secret)
    end
  end
end