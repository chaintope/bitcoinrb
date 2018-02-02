require 'spec_helper'
include Bitcoin::Opcodes

describe Bitcoin do

  it 'has a version number' do
    expect(Bitcoin::VERSION).not_to be nil
  end

  describe '#chain_params' do
    it 'should be change bitcoin network' do
      Bitcoin.chain_params = :mainnet
      expect(Bitcoin.chain_params.network).to eq('mainnet')
      Bitcoin.chain_params = :testnet
      expect(Bitcoin.chain_params.network).to eq('testnet')
      Bitcoin.chain_params = :regtest
      expect(Bitcoin.chain_params.network).to eq('regtest')
      expect { Bitcoin.chain_params = :hoge }.to raise_error(RuntimeError)
    end
  end
  
  describe '#pushdata?' do
    it 'should be judged' do
      expect(OP_DUP.chr.pushdata?).to be false
      expect(OP_HASH160.chr.pushdata?).to be false
      expect('1446c2fbfbecc99a63148fa076de58cf29b0bcf0b0'.htb.pushdata?).to be true
      expect(1.chr.pushdata?).to be true
      expect('ba'.htb.pushdata?).to be false
    end
  end

  describe '#opcode' do
    it 'should be return opcode' do
      expect(OP_DUP.chr.opcode).to eq(OP_DUP)
      expect(OP_1.chr.opcode).to eq(OP_1)
      expect(OP_HASH160.chr.opcode).to eq(OP_HASH160)
      expect(OP_PUSHDATA1.chr.opcode).to eq(OP_PUSHDATA1)
      expect('1446c2fbfbecc99a63148fa076de58cf29b0bcf0b0'.htb.opcode?).to be false
    end
  end

  describe '#pushed_data' do
    it 'should get pushed data' do
      expect('010b'.htb.pushed_data).to eq('0b'.htb)
      expect('4c0107')
    end
  end

  class Test
    def initialize
      @foo = ["bar"]
    end
  end
  describe '#build_json' do
    it 'should handle string in array' do
      expect(["a", "b", "c"].build_json).to eq "[\"a\",\"b\",\"c\"]"
      expect(Test.new.build_json).to eq "{\"foo\":[\"bar\"]}"
    end
  end
end
