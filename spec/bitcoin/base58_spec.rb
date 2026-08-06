require 'spec_helper'

describe Bitcoin::Base58 do

  describe 'encode/decode' do
    f = fixture_file('base58_encode_decode.json')
    f.each do |hex, encoded|
      it "should be encoded/decoded #{hex}, #{encoded}" do
        expect(Bitcoin::Base58.encode(hex)).to eq(encoded)
        expect(Bitcoin::Base58.decode(encoded)).to eq(hex)
      end
    end
  end

  describe '#decode' do
    context 'contains a character which is not in the alphabet' do
      it 'should raise error' do
        expect { Bitcoin::Base58.decode('10I') }.to raise_error(
          ArgumentError, 'Value passed not a valid Base58 String.')
      end
    end

    context 'longer than MAX_LENGTH' do
      # Decoding is quadratic in the length of the input, so an unbounded string is a way to
      # burn CPU. The longest value Bitcoin encodes with Base58 is an extended key.
      it 'should raise error' do
        expect { Bitcoin::Base58.decode('z' * (Bitcoin::Base58::MAX_LENGTH + 1)) }.to raise_error(
          ArgumentError, "Base58 string must not be longer than #{Bitcoin::Base58::MAX_LENGTH} characters.")
      end
    end

    context 'at MAX_LENGTH' do
      it 'should be decoded' do
        expect { Bitcoin::Base58.decode('z' * Bitcoin::Base58::MAX_LENGTH) }.not_to raise_error
      end
    end

    context 'extended key' do
      subject {
        Bitcoin::Base58.decode(
          'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8')
      }
      it 'should be decoded' do
        expect(subject).to eq(
          '0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2ab473b21')
      end
    end
  end

end
