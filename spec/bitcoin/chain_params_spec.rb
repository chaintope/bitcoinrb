require 'spec_helper'

describe Bitcoin::ChainParams do

  describe 'load params' do

    context 'mainnet' do
      subject{Bitcoin::ChainParams.mainnet}
      it do
        expect(subject.address_version).to eq('00')
        expect(subject.mainnet?).to be true
        expect(subject.testnet?).to be false
        expect(subject.regtest?).to be false
        expect(subject.genesis_block.header.to_payload.bth).to eq('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c')
        expect(subject.genesis_block.header.hash).to eq('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')
      end
    end

    context 'testnet' do
      subject{Bitcoin::ChainParams.testnet}
      it do
        expect(subject.address_version).to eq('6f')
        expect(subject.mainnet?).to be false
        expect(subject.testnet?).to be true
        expect(subject.regtest?).to be false
        expect(subject.genesis_block.header.to_payload.bth).to eq('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18')
        expect(subject.genesis_block.header.hash).to eq('000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943')
      end
    end

    context 'regtest' do
      subject{Bitcoin::ChainParams.regtest}
      it do
        expect(subject.default_port).to eq(18444)
        expect(subject.mainnet?).to be false
        expect(subject.testnet?).to be false
        expect(subject.regtest?).to be true
        expect(subject.genesis_block.header.to_payload.bth).to eq('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000')
        expect(subject.genesis_block.header.hash).to eq('0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206')
      end
    end
  end

end