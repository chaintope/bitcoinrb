require 'spec_helper'

describe Bitcoin::Base58 do

  describe 'encode/decode' do
    it 'should be encoded/decoded' do
      f = fixture_file('base58_encode_decode.json')
      f.each do |hex, encoded|
        expect(Bitcoin::Base58.encode(hex)).to eq(encoded)
        expect(Bitcoin::Base58.decode(encoded)).to eq(hex)
      end
    end
  end

end