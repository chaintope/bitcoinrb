require 'spec_helper'

describe Bitcoin::Key do

  describe '#from_wif' do
    context 'mainnet', network: :mainnet do
      subject { Bitcoin::Key.from_wif('KxJkzWsRQmr2bdU9TdWDFhXxg9nsELSEQojEQFZMFqJsHTBSXpP9') }
      it 'should be parse' do
        expect(subject.priv_key).to eq('206f3acb5b7ac66dacf87910bb0b04bed78284b9b50c0d061705a44447a947ff')
        expect(subject.pub_key).to eq('020025aeb645b64b632c91d135683e227cb508ebb1766c65ee40405f53b8f1bb3a')
        expect(subject.p2pkh).to eq('191arn68nSLRiNJXD8srnmw4bRykBkVv6o')
      end
    end

    context 'testnet', network: :testnet do
      subject { Bitcoin::Key.from_wif('cPaJYBMDLjQp5gSUHnBfhX4Rgj95ekBS6oBttwQLw3qfsKKcDfuB') }
      it 'should be parse' do
        expect(subject.compressed?).to be true
        expect(subject.priv_key).to eq('3b7845c14659d875b2e50093f07f950c96271f6cc71a3531750c5a567084d438')
        expect(subject.pub_key).to eq('0292ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c9')
        expect(subject.p2pkh).to eq('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F1')
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

end