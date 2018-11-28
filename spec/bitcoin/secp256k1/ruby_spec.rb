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

  describe '#sign_data/#verify_data', use_secp256k1: true do
    it 'should be signed' do
      message = 'message'.htb
      priv_key = '3b7845c14659d875b2e50093f07f950c96271f6cc71a3531750c5a567084d438'
      pub_key = '0292ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c9'
      sig = Bitcoin::Secp256k1::Ruby.sign_data(message, priv_key, nil)
      expect(Bitcoin::Secp256k1::Ruby.verify_sig(message, sig, pub_key)).to be true

      # generate signature compatible with RFC 6979
      priv_key = 'bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866'
      message = '63cec688ee06a91e913875356dd4dea2f8e0f2a2659885372da2a37e32c7532e'.htb
      signature = '30450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed'
      expect(Bitcoin::Secp256k1::Ruby.sign_data(message, priv_key, nil).bth).to eq(signature)

      priv_key = Bitcoin::Key.generate.priv_key
      secp256k1_sig = Bitcoin::Secp256k1::Native.sign_data(message, priv_key, nil)
      ruby_sig = Bitcoin::Secp256k1::Ruby.sign_data(message, priv_key, nil)
      expect(ruby_sig.bth).to eq(secp256k1_sig.bth)
    end
  end

end