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

    context 'mainnet', network: :mainnet do
      it 'should be generate P2PKH script' do
        expect(subject.to_payload.bytesize).to eq(25)
        expect(subject.to_payload).to eq('76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac'.htb)
        expect(subject.to_s).to eq('OP_DUP OP_HASH160 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0 OP_EQUALVERIFY OP_CHECKSIG')
        expect(subject.p2pkh?).to be true
        expect(subject.p2sh?).to be false
        expect(subject.p2wpkh?).to be false
        expect(subject.p2wsh?).to be false
        expect(subject.to_addr).to eq('17T9tBC2dSpusL1rhT4T4AV4if963Tpfym')
      end
    end

    context 'testnet' do
      it 'should be generate P2PKH script' do
        expect(subject.to_addr).to eq('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F1')
      end
    end
  end

  describe 'p2wpkh script' do
    subject { Bitcoin::Script.to_p2wpkh('46c2fbfbecc99a63148fa076de58cf29b0bcf0b0') }

    context 'mainnet', network: :mainnet do
      it 'should be generate P2WPKH script' do
        expect(subject.to_payload.bytesize).to eq(22)
        expect(subject.to_payload).to eq('001446c2fbfbecc99a63148fa076de58cf29b0bcf0b0'.htb)
        expect(subject.to_s).to eq('0 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0')
        expect(subject.p2pkh?).to be false
        expect(subject.p2sh?).to be false
        expect(subject.p2wpkh?).to be true
        expect(subject.p2wsh?).to be false
        expect(subject.to_addr).to eq('bc1qgmp0h7lvexdxx9y05pmdukx09xcteu9svvvxlw')
      end
    end

    context 'testnet' do
      it 'should be generate P2WPKH script' do
        expect(subject.to_addr).to eq('tb1qgmp0h7lvexdxx9y05pmdukx09xcteu9sx2h4ya')
      end
    end

  end

  describe 'p2sh script' do
    subject {
      k1 = '021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9'
      k2 = '032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35'
      Bitcoin::Script.to_p2sh_multisig_script(1, [k1, k2])
    }
    context 'mainnet', network: :mainnet do
      it 'should be generate P2SH script' do
        expect(subject.length).to eq(2)
        expect(subject[0].to_payload.bth).to eq('a9147620a79e8657d066cff10e21228bf983cf546ac687')
        expect(subject[0].to_s).to eq('OP_HASH160 7620a79e8657d066cff10e21228bf983cf546ac6 OP_EQUAL')
        expect(subject[0].p2pkh?).to be false
        expect(subject[0].p2sh?).to be true
        expect(subject[0].p2wpkh?).to be false
        expect(subject[0].p2wsh?).to be false
        expect(subject[0].to_addr).to eq('3CTcn59uJ89wCsQbeiy8AGLydXE9mh6Yrr')
        expect(subject[1].to_payload.bth).to eq('5121021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e921032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e3552ae')
        expect(subject[1].to_s).to eq('1 021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9 032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35 2 OP_CHECKMULTISIG')
        expect(subject[1].to_addr).to be nil
      end
    end

    context 'testnet' do
      it 'should be generate P2SH script' do
        expect(subject[0].to_addr).to eq('2N41pqp5vuafHQf39KraznDLEqsSKaKmrij')
        expect(subject[1].to_addr).to be nil
      end
    end
  end

  describe 'p2wsh script' do
    subject {
      k1 = '021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9'
      k2 = '032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35'
      redeem_script = Bitcoin::Script.to_multisig_script(1, [k1, k2])
      Bitcoin::Script.to_p2wsh(redeem_script)
    }

    context 'mainnet', network: :mainnet do
      it 'should be generate P2WSH script' do
        expect(subject.to_payload).to eq('00203ce1c71303e564430e0c5721727739290046302a9674f1d67a249cfd2ce7d3fd'.htb)
        expect(subject.to_s).to eq('0 3ce1c71303e564430e0c5721727739290046302a9674f1d67a249cfd2ce7d3fd')
        expect(subject.p2pkh?).to be false
        expect(subject.p2sh?).to be false
        expect(subject.p2wpkh?).to be false
        expect(subject.p2wsh?).to be true
        expect(subject.to_addr).to eq('bc1q8nsuwycru4jyxrsv2ushyaee9yqyvvp2je60r4n6yjw06t88607s264w7g')
      end
    end

    context 'testnet' do
      it 'should be generate P2WSH script' do
        expect(subject.to_addr).to eq('tb1q8nsuwycru4jyxrsv2ushyaee9yqyvvp2je60r4n6yjw06t88607sajrpy8')
      end
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

  describe '#from_string' do
    it 'should be generate' do
      p2pkh = Bitcoin::Script.from_string('OP_DUP OP_HASH160 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0 OP_EQUALVERIFY OP_CHECKSIG')
      expect(p2pkh.to_payload).to eq('76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac'.htb)
      expect(p2pkh.to_s).to eq('OP_DUP OP_HASH160 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0 OP_EQUALVERIFY OP_CHECKSIG')

      p2sh = Bitcoin::Script.from_string('1 021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9 032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35 2 OP_CHECKMULTISIG')
      expect(p2sh.to_s).to eq('1 021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9 032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35 2 OP_CHECKMULTISIG')
      expect(p2sh.to_payload).to eq('5121021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e921032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e3552ae'.htb)

      p2wpkh = Bitcoin::Script.from_string('0 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0')
      expect(p2wpkh.to_s).to eq('0 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0')
      expect(p2wpkh.to_payload).to eq('001446c2fbfbecc99a63148fa076de58cf29b0bcf0b0'.htb)
    end
  end

  describe '#push_only?' do
    it 'should be judged' do
      expect(Bitcoin::Script.new.push_only?).to be true
      expect(Bitcoin::Script.from_string('0 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0').push_only?).to be false
      expect(Bitcoin::Script.from_string('46c2fbfbecc99a63148fa076de58cf29b0bcf0b0 OP_EQUAL').push_only?).to be false
      expect(Bitcoin::Script.from_string('3044022009ea34cf915708efa8d0fb8a784d4d9e3108ca8da4b017261dd029246c857ebc02201ae570e2d8a262bd9a2a157f473f4089f7eae5a8f54ff9f114f624557eda742001 02effb2edfcf826d43027feae226143bdac058ad2e87b7cec26f97af2d357ddefa').push_only?).to be false
    end
  end

end