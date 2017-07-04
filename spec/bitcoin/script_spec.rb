require 'spec_helper'
include Bitcoin::Opcodes

describe Bitcoin::Script do

  describe '#append_data' do
    context 'data < 0xff' do
      subject { Bitcoin::Script.new << 'foo' }
      it 'should be append' do
        expect(subject.to_payload.bth).to eq('02f880')
      end
    end
    context '0xff < data < 0xffff' do
      subject { Bitcoin::Script.new << 'f' * 256 }
      it 'should be append' do
        expect(subject.to_payload).to eq(('4c80ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff').htb)
      end
    end
  end

  describe 'p2pkh script' do
    subject { Bitcoin::Script.to_p2pkh('46c2fbfbecc99a63148fa076de58cf29b0bcf0b0') }
    it 'should be generate P2PKH script' do
      expect(subject.to_payload.bytesize).to eq(25)
      expect(subject.to_payload).to eq('76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac'.htb)
      expect(subject.to_s).to eq('OP_DUP OP_HASH160 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0 OP_EQUALVERIFY OP_CHECKSIG')
      expect(subject.p2pkh?).to be true
      expect(subject.p2sh?).to be false
      expect(subject.p2wpkh?).to be false
      expect(subject.to_addr).to eq('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F1')
    end
  end

  describe 'parse from payload' do
    subject {
      Bitcoin::Script.parse_from_payload('76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac'.htb)
    }
    it 'should be parsed' do
      expect(subject.to_s).to eq('OP_DUP OP_HASH160 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0 OP_EQUALVERIFY OP_CHECKSIG')
      expect(subject.p2pkh?).to be true
    end
  end

  describe 'opcode?/pushdata?' do
    it 'should be judged' do
      expect(Bitcoin::Script.opcode?(OP_DUP.chr)).to be true
      expect(Bitcoin::Script.opcode?(OP_HASH160.chr)).to be true
      expect(Bitcoin::Script.opcode?('1446c2fbfbecc99a63148fa076de58cf29b0bcf0b0'.htb)).to be false
      expect(Bitcoin::Script.opcode?(OP_PUSHDATA1.chr)).to be false
    end
  end

end