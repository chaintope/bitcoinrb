require 'spec_helper'

RSpec.describe Bitcoin::BIP324 do

  let(:decode_vectors) { read_csv('bip324/ellswift_decode_test_vectors.csv') }
  let(:inv_vectors) { read_csv('bip324/xswiftec_inv_test_vectors.csv') }

  describe '#decode' do
    context 'native', use_secp256k1: true do
      it { test_vectors }
    end

    context 'ruby' do
      it { test_vectors }
    end

    def test_vectors
      decode_vectors.each do |v|
        k = Bitcoin::BIP324::EllSwiftPubkey.new(v['ellswift'])
        expect(k.decode.xonly_pubkey).to eq(v['x'])
      end
    end
  end

  describe "xswiftec_inv" do
    it do
      inv_vectors.each do |v|
        8.times do |c|
          r = described_class.xswiftec_inv(v['x'], v['u'], c)
          if r.nil?
            expect(v["case#{c}_t"]).to be nil
          else
            expect(r).to eq(v["case#{c}_t"])
            expect(described_class.xswiftec(v['u'], r))
          end
        end
      end
    end
  end
end
