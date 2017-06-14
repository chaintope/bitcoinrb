require 'spec_helper'

describe Bitcoin::ChainParams do

  describe 'load params' do

    context 'mainnet' do
      subject{Bitcoin::ChainParams.mainnet}
      it do
        expect(subject.address_version).to eq('00')
        expect(subject.genesis_hash).to eq('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')
        expect(subject.mainnet?).to be true
        expect(subject.testnet?).to be false
        expect(subject.regtest?).to be false
      end
    end

    context 'testnet' do
      subject{Bitcoin::ChainParams.testnet}
      it do
        expect(subject.address_version).to eq('6f')
        expect(subject.genesis_hash).to eq('000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943')
        expect(subject.mainnet?).to be false
        expect(subject.testnet?).to be true
        expect(subject.regtest?).to be false
      end
    end

    context 'regtest' do
      subject{Bitcoin::ChainParams.regtest}
      it do
        expect(subject.default_port).to eq(18444)
        expect(subject.genesis_hash).to eq('0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206')
        expect(subject.mainnet?).to be false
        expect(subject.testnet?).to be false
        expect(subject.regtest?).to be true
      end
    end
  end

end