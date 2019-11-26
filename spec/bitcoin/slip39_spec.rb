require 'spec_helper'

describe Bitcoin::SLIP39 do

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
        end
      end
    end
  end

end