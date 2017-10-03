require 'spec_helper'

describe Bitcoin::Secp256k1::Ruby do

  describe '#generate_key_pair' do
    context 'compressed' do
      subject { Bitcoin::Secp256k1::Ruby.generate_key_pair }
      it 'should be generate' do
        expect(subject.length).to eq(2)
        # privkey
        expect(subject[0].htb.bytesize).to eq(32)
        # pubkey
        expect(subject[1].htb.bytesize).to eq(33)
        expect(['02', '03'].include?(subject[1].htb[0].bth)).to be true
      end
    end

    context 'uncompressed' do
      subject { Bitcoin::Secp256k1::Ruby.generate_key_pair(compressed: false) }
      it 'should be generate' do
        expect(subject.length).to eq(2)
        # privkey
        expect(subject[0].htb.bytesize).to eq(32)
        # pubkey
        expect(subject[1].htb.bytesize).to eq(65)
        expect(subject[1].htb[0].bth).to eq('04')
      end
    end
  end

  describe '#generate_key' do
    context 'compressed' do
      subject { Bitcoin::Secp256k1::Ruby.generate_key }
      it 'should be generate' do
        expect(subject.compressed?).to be true
      end
    end

    context 'uncompressed' do
      subject { Bitcoin::Secp256k1::Ruby.generate_key(compressed: false) }
      it 'should be generate' do
        expect(subject.compressed?).to be false
      end
    end
  end

  describe '#sign_data/#verify_data' do
    it 'should be signed' do
      message = 'message'
      priv_key = '3b7845c14659d875b2e50093f07f950c96271f6cc71a3531750c5a567084d438'
      pub_key = '0292ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c9'
      sig = Bitcoin::Secp256k1::Ruby.sign_data(message, priv_key)
      expect(Bitcoin::Secp256k1::Ruby.verify_sig(message, sig, pub_key)).to be true
    end
  end

end