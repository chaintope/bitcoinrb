require 'spec_helper'

describe Bitcoin::Key do

  describe '#from_wif' do
    context 'mainnet', network: :mainnet do
      subject { Bitcoin::Key.from_wif('KxJkzWsRQmr2bdU9TdWDFhXxg9nsELSEQojEQFZMFqJsHTBSXpP9') }
      it 'should be parse' do
        expect(subject.priv_key).to eq('206f3acb5b7ac66dacf87910bb0b04bed78284b9b50c0d061705a44447a947ff')
        expect(subject.pubkey).to eq('020025aeb645b64b632c91d135683e227cb508ebb1766c65ee40405f53b8f1bb3a')
        expect(subject.to_p2pkh).to eq('191arn68nSLRiNJXD8srnmw4bRykBkVv6o')
        expect(subject.to_p2wpkh).to eq('bc1q2lw52zhd202wxhf42k3y4e7m70sg578ver73dn')
      end
    end

    context 'testnet', network: :testnet do
      subject { Bitcoin::Key.from_wif('cPaJYBMDLjQp5gSUHnBfhX4Rgj95ekBS6oBttwQLw3qfsKKcDfuB') }
      it 'should be parse' do
        expect(subject.compressed?).to be true
        expect(subject.priv_key).to eq('3b7845c14659d875b2e50093f07f950c96271f6cc71a3531750c5a567084d438')
        expect(subject.pubkey).to eq('0292ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c9')
        expect(subject.to_p2pkh).to eq('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F1')
      end
    end
  end

  describe '#to_wif' do
    context 'mainnet', network: :mainnet do
      subject { Bitcoin::Key.new(priv_key: '206f3acb5b7ac66dacf87910bb0b04bed78284b9b50c0d061705a44447a947ff').to_wif }
      it 'should be export' do
        expect(subject).to eq('KxJkzWsRQmr2bdU9TdWDFhXxg9nsELSEQojEQFZMFqJsHTBSXpP9')
      end
    end
    context 'testnet' do
      subject { Bitcoin::Key.new(priv_key: '3b7845c14659d875b2e50093f07f950c96271f6cc71a3531750c5a567084d438').to_wif }
      it 'should be export' do
        expect(subject).to eq('cPaJYBMDLjQp5gSUHnBfhX4Rgj95ekBS6oBttwQLw3qfsKKcDfuB')
      end
    end
  end

  describe '#compress_or_uncompress_pubkey?' do
    it 'should be checked' do
      expect(Bitcoin::Key.compress_or_uncompress_pubkey?('02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0')).to be true
      expect(Bitcoin::Key.compress_or_uncompress_pubkey?('030efdac25af91a7d2227481a72d467d3cbfbf9593c39da48590dcf2d10b266f47')).to be true
      expect(Bitcoin::Key.compress_or_uncompress_pubkey?('04a232272863a59dfd3f5f643bfc7558711ce59df1fb1f3102b19aedb4f241db8f1fc4286d3ab3f8b6c60fc0e0d9f827745b09f1473c8f6ae6f915653765f5d313')).to be true
      expect(Bitcoin::Key.compress_or_uncompress_pubkey?('02a232272863a59dfd3f5f643bfc7558711ce59df1fb1f3102b19aedb4f241db8f1fc4286d3ab3f8b6c60fc0e0d9f827745b09f1473c8f6ae6f915653765f5d313')).to be false
      expect(Bitcoin::Key.compress_or_uncompress_pubkey?('03a232272863a59dfd3f5f643bfc7558711ce59df1fb1f3102b19aedb4f241db8f1fc4286d3ab3f8b6c60fc0e0d9f827745b09f1473c8f6ae6f915653765f5d313')).to be false
      expect(Bitcoin::Key.compress_or_uncompress_pubkey?('')).to be false
      expect(Bitcoin::Key.compress_or_uncompress_pubkey?('000efdac25af91a7d2227481a72d467d3cbfbf9593c39da48590dcf2d10b266f47')).to be false
      expect(Bitcoin::Key.compress_or_uncompress_pubkey?('040efdac25af91a7d2227481a72d467d3cbfbf9593c39da48590dcf2d10b266f47')).to be false
    end
  end

  describe '#compress_pubkey?' do
    it 'should be checked' do
      expect(Bitcoin::Key.compress_pubkey?('02865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0')).to be true
      expect(Bitcoin::Key.compress_pubkey?('030efdac25af91a7d2227481a72d467d3cbfbf9593c39da48590dcf2d10b266f47')).to be true
      expect(Bitcoin::Key.compress_pubkey?('04a232272863a59dfd3f5f643bfc7558711ce59df1fb1f3102b19aedb4f241db8f1fc4286d3ab3f8b6c60fc0e0d9f827745b09f1473c8f6ae6f915653765f5d313')).to be false
      expect(Bitcoin::Key.compress_or_uncompress_pubkey?('')).to be false
      expect(Bitcoin::Key.compress_or_uncompress_pubkey?('040efdac25af91a7d2227481a72d467d3cbfbf9593c39da48590dcf2d10b266f47')).to be false
    end
  end

  describe '#to_point' do
    context 'compress pubkey' do
      subject {
        Bitcoin::Key.new(pubkey: '0292ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c9').to_point
      }
      it 'should be generate ec point' do
        expect(subject.x).to eq(66459088590212380792611386255453021887227364243207655103300857960258170950345)
        expect(subject.y).to eq(35473366296081526532737740169602173612426578347181408584726802824997634845606)
        expect(subject.group).to eq(Bitcoin::Secp256k1::GROUP)
      end
    end

    context 'uncompress pubkey' do
      subject {
        Bitcoin::Key.new(pubkey: '0492ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c94e6d36bc82983001902d48cb877671a4f50b40aa5d794ebdea1bdf76e36c2ba6',
                         compressed: false).to_point
      }
      it 'should be generate ec point' do
        expect(subject.x).to eq(66459088590212380792611386255453021887227364243207655103300857960258170950345)
        expect(subject.y).to eq(35473366296081526532737740169602173612426578347181408584726802824997634845606)
        expect(subject.group).to eq(Bitcoin::Secp256k1::GROUP)
      end
    end
  end

  describe '#sign and verify' do
    it 'should be success' do
      message = 'message'.htb
      key = Bitcoin::Key.generate
      sig = key.sign(message)
      expect(key.verify(sig, message)).to be true
    end
  end

  describe 'private key range check' do
    context 'on curve' do
      it 'not raise error' do
        expect{Bitcoin::Key.new(priv_key: '01')}.not_to raise_error
        expect{Bitcoin::Key.new(priv_key: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140')}.not_to raise_error
      end
    end

    context 'not on curve' do
      it 'raise error' do
        expect{Bitcoin::Key.new(priv_key: '00')}.to raise_error(ArgumentError)
        expect{Bitcoin::Key.new(priv_key: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141')}.to raise_error(ArgumentError)
      end
    end
  end

end