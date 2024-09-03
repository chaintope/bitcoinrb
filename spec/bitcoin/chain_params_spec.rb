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
        expect(subject.signet?).to be false
        expect(subject.testnet4?).to be false
        expect(subject.genesis_block.header.to_hex).to eq('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c')
        expect(subject.genesis_block.header.block_hash).to eq('6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000')
        expect(subject.dust_relay_fee).to eq(Bitcoin::DUST_RELAY_TX_FEE)
      end
    end

    context 'testnet' do
      subject{Bitcoin::ChainParams.testnet}
      it do
        expect(subject.address_version).to eq('6f')
        expect(subject.mainnet?).to be false
        expect(subject.testnet?).to be true
        expect(subject.regtest?).to be false
        expect(subject.signet?).to be false
        expect(subject.testnet4?).to be false
        expect(subject.genesis_block.header.to_hex).to eq('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18')
        expect(subject.genesis_block.header.block_hash).to eq('43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000')
        expect(subject.dust_relay_fee).to eq(Bitcoin::DUST_RELAY_TX_FEE)
      end
    end

    context 'regtest' do
      subject{Bitcoin::ChainParams.regtest}
      it do
        expect(subject.default_port).to eq(18444)
        expect(subject.mainnet?).to be false
        expect(subject.testnet?).to be false
        expect(subject.regtest?).to be true
        expect(subject.signet?).to be false
        expect(subject.testnet4?).to be false
        expect(subject.genesis_block.header.to_hex).to eq('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000')
        expect(subject.genesis_block.header.block_hash).to eq('06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f')
        expect(subject.dust_relay_fee).to eq(3600)
      end
    end

    # https://github.com/bitcoin/bips/blob/master/bip-0325.mediawiki
    context 'signet' do
      subject{Bitcoin::ChainParams.signet}
      it do
        expect(subject.default_port).to eq(38333)
        expect(subject.mainnet?).to be false
        expect(subject.testnet?).to be false
        expect(subject.regtest?).to be false
        expect(subject.signet?).to be true
        expect(subject.testnet4?).to be false
        expect(subject.genesis_block.header.to_hex).to eq('0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a008f4d5fae77031e8ad22203')
        expect(subject.genesis_block.header.block_id).to eq('00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6')
      end
    end

    # https://github.com/bitcoin/bips/blob/master/bip-0094.mediawiki
    context 'testnet4' do
      subject{Bitcoin::ChainParams.testnet4}
      it do
        expect(subject.default_port).to eq(48333)
        expect(subject.mainnet?).to be false
        expect(subject.testnet?).to be false
        expect(subject.regtest?).to be false
        expect(subject.signet?).to be false
        expect(subject.testnet4?).to be true
        expect(subject.magic_head).to eq('1c163f28')
        expect(subject.bip34_height).to eq(1)

        expect(subject.genesis_block.header.to_hex).to eq('0100000000000000000000000000000000000000000000000000000000000000000000004e7b2b9128fe0291db0693af2ae418b767e657cd407e80cb1434221eaea7a07a046f3566ffff001dbb0c7817')
        expect(subject.genesis_block.header.block_id).to eq('00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043')
      end
    end
  end

end