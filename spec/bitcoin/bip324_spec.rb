require 'spec_helper'

RSpec.describe Bitcoin::BIP324 do

  let(:decode_vectors) {read_csv('bip324/ellswift_decode_test_vectors.csv')}

  describe '#decode' do
    context 'native', use_secp256k1: true do
      it do
        test_vectors
      end
    end

    context 'ruby' do
      it do
        test_vectors
      end
    end

    def test_vectors
      decode_vectors.each do |v|
        k = Bitcoin::BIP324::EllSwiftPubkey.new(v['ellswift'])
        expect(k.decode.xonly_pubkey).to eq(v['x'])
      end
    end
  end
end
