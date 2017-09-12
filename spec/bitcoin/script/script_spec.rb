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
        expect(subject.to_payload.bth).to eq('4c80ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
      end
    end
    context 'int value include' do
      it 'should be append' do
        s = Bitcoin::Script.new << OP_1NEGATE << Bitcoin::Script.encode_number(1000) << OP_ADD
        expect(s.to_payload.bth).to eq('4f02e80393')
        expect(s.to_s).to eq('OP_1NEGATE e803 OP_ADD')
        s = Bitcoin::Script.new << OP_1NEGATE << Bitcoin::Script.encode_number(100) << OP_ADD
        expect(s.to_payload.bth).to eq('4f016493')
        # negative value
        s = Bitcoin::Script.new << OP_1NEGATE << Bitcoin::Script.encode_number(-1000) << OP_ADD
        expect(s.to_payload.bth).to eq('4f02e88393')
        expect(s.to_s).to eq('OP_1NEGATE e883 OP_ADD')
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
        expect(subject.multisig?).to be false
        expect(subject.op_return?).to be false
        expect(subject.standard?).to be true
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
        expect(subject.multisig?).to be false
        expect(subject.op_return?).to be false
        expect(subject.standard?).to be true
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
        expect(subject[0].multisig?).to be false
        expect(subject[0].op_return?).to be false
        expect(subject[0].standard?).to be true
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
        expect(subject.to_payload.bth).to eq('00203ce1c71303e564430e0c5721727739290046302a9674f1d67a249cfd2ce7d3fd')
        expect(subject.to_s).to eq('0 3ce1c71303e564430e0c5721727739290046302a9674f1d67a249cfd2ce7d3fd')
        expect(subject.p2pkh?).to be false
        expect(subject.p2sh?).to be false
        expect(subject.p2wpkh?).to be false
        expect(subject.p2wsh?).to be true
        expect(subject.multisig?).to be false
        expect(subject.op_return?).to be false
        expect(subject.standard?).to be true
        expect(subject.to_addr).to eq('bc1q8nsuwycru4jyxrsv2ushyaee9yqyvvp2je60r4n6yjw06t88607s264w7g')
      end
    end

    context 'testnet' do
      it 'should be generate P2WSH script' do
        expect(subject.to_addr).to eq('tb1q8nsuwycru4jyxrsv2ushyaee9yqyvvp2je60r4n6yjw06t88607sajrpy8')
      end
    end
  end

  describe 'multisig script' do
    subject {
      k1 = '021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9'
      k2 = '032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35'
      Bitcoin::Script.to_multisig_script(1, [k1, k2])
    }
    it 'should treat as multisig' do
      expect(subject.p2pkh?).to be false
      expect(subject.p2sh?).to be false
      expect(subject.p2wpkh?).to be false
      expect(subject.p2wsh?).to be false
      expect(subject.multisig?).to be true
      expect(subject.op_return?).to be false
      expect(subject.standard?).to be true
    end
  end

  describe 'op_return script' do
    context 'within MAX_OP_RETURN_RELAY' do
      subject {
        Bitcoin::Script.new << OP_RETURN << '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38'
      }
      it 'should treat as multisig' do
        expect(subject.p2pkh?).to be false
        expect(subject.p2sh?).to be false
        expect(subject.p2wpkh?).to be false
        expect(subject.p2wsh?).to be false
        expect(subject.multisig?).to be false
        expect(subject.op_return?).to be true
        expect(subject.standard?).to be true
      end
    end

    context 'over MAX_OP_RETURN_RELAY' do
      subject {
        Bitcoin::Script.new << OP_RETURN << '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3800'
      }
      it 'should correct op_return, but not standard' do
        expect(subject.op_return?).to be true
        expect(subject.standard?).to be false
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

      pushdata = Bitcoin::Script.from_string('46c2fbfbecc99a63148fa076de58cf29b0bcf0b0')
      expect(pushdata.to_s).to eq('46c2fbfbecc99a63148fa076de58cf29b0bcf0b0')
      expect(pushdata.to_payload).to eq('1446c2fbfbecc99a63148fa076de58cf29b0bcf0b0'.htb)
    end
  end

  describe '#push_only?' do
    it 'should be judged' do
      expect(Bitcoin::Script.new.push_only?).to be true
      expect(Bitcoin::Script.from_string('0 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0').push_only?).to be true
      expect(Bitcoin::Script.from_string('46c2fbfbecc99a63148fa076de58cf29b0bcf0b0 OP_EQUAL').push_only?).to be false
      expect(Bitcoin::Script.from_string('46c2fbfbecc99a63148fa076de58cf29b0bcf0b0').push_only?).to be true
      expect(Bitcoin::Script.from_string('3044022009ea34cf915708efa8d0fb8a784d4d9e3108ca8da4b017261dd029246c857ebc02201ae570e2d8a262bd9a2a157f473f4089f7eae5a8f54ff9f114f624557eda742001 02effb2edfcf826d43027feae226143bdac058ad2e87b7cec26f97af2d357ddefa').push_only?).to be true
    end
  end

  describe '#encode_number' do
    it 'should be encoded' do
      expect(Bitcoin::Script.encode_number(1000)).to eq('e803')
      expect(Bitcoin::Script.encode_number(100)).to eq('64')
      expect(Bitcoin::Script.encode_number(-1000)).to eq('e883')
      expect(Bitcoin::Script.encode_number(127)).to eq('7f')
      expect(Bitcoin::Script.encode_number(128)).to eq('8000')
      expect(Bitcoin::Script.encode_number(129)).to eq('8100')
      expect(Bitcoin::Script.encode_number(-127)).to eq('ff')
      expect(Bitcoin::Script.encode_number(-128)).to eq('8080')
      expect(Bitcoin::Script.encode_number(-129)).to eq('8180')
      expect(Bitcoin::Script.encode_number(0)).to eq('')
    end
  end

  describe '#decode_number' do
    it 'should be decoded' do
      expect(Bitcoin::Script.decode_number('e803')).to eq(1000)
      expect(Bitcoin::Script.decode_number('64')).to eq(100)
      expect(Bitcoin::Script.decode_number('e883')).to eq(-1000)
      expect(Bitcoin::Script.decode_number('7f')).to eq(127)
      expect(Bitcoin::Script.decode_number('8000')).to eq(128)
      expect(Bitcoin::Script.decode_number('8100')).to eq(129)
      expect(Bitcoin::Script.decode_number('ff')).to eq(-127)
      expect(Bitcoin::Script.decode_number('8080')).to eq(-128)
      expect(Bitcoin::Script.decode_number('8180')).to eq(-129)
      expect(Bitcoin::Script.decode_number('')).to eq(0)
    end
  end

  describe '#subscript' do
    subject {
      Bitcoin::Script.new << OP_DUP << OP_HASH160 << 'pubkeyhash' << OP_EQUALVERIFY << OP_CHECKSIG
    }
    it 'should be split' do
      expect(subject.subscript(0..-1)).to eq(subject)
      expect(subject.subscript(3..-1)).to eq(Bitcoin::Script.new << OP_EQUALVERIFY << OP_CHECKSIG)
    end
  end

  describe '#witness_program?' do
    it 'should be judge' do
      expect(Bitcoin::Script.from_string('0 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d').witness_program?).to be true
      expect(Bitcoin::Script.from_string('0 62').witness_program?).to be false
      expect(Bitcoin::Script.from_string('0 6234').witness_program?).to be true
      expect(Bitcoin::Script.from_string('0 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d0000000000000000').witness_program?).to be true
      expect(Bitcoin::Script.from_string('0 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d000000000000000000').witness_program?).to be false
      expect(Bitcoin::Script.from_string('1 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d').witness_program?).to be true
      expect(Bitcoin::Script.from_string('0000 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d').witness_program?).to be false
    end
  end

  describe '#witness_data' do
    it 'should be return version and program' do
      script = Bitcoin::Script.from_string('0 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d')
      data = script.witness_data
      expect(data.size).to eq(2)
      expect(data[0]).to eq(0)
      expect(data[1].bth).to eq('6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d')
    end
  end

  describe '#find_and_delete' do
    it 'should be delete' do
      s = Bitcoin::Script.new << OP_1 << OP_2
      d = Bitcoin::Script.new
      expect(s.find_and_delete(d)).to eq(s)

      s = Bitcoin::Script.new << OP_1 << OP_2 << OP_3
      d = Bitcoin::Script.new << OP_2
      expect(s.find_and_delete(d)).to eq(Bitcoin::Script.new << OP_1 << OP_3)

      s = Bitcoin::Script.new << OP_3 << OP_1 << OP_3 << OP_3 << OP_4 << OP_3
      d = Bitcoin::Script.new << OP_3
      expect(s.find_and_delete(d)).to eq(Bitcoin::Script.new << OP_1 << OP_4)

      s = Bitcoin::Script.parse_from_payload('0302ff03'.htb) # PUSH 0x02ff03 onto stack
      d = Bitcoin::Script.parse_from_payload('0302ff03'.htb)
      expect(s.find_and_delete(d)).to eq(Bitcoin::Script.new)

      s = Bitcoin::Script.parse_from_payload('0302ff030302ff03'.htb) # PUSH 0x2ff03 PUSH 0x2ff03
      d = Bitcoin::Script.parse_from_payload('0302ff03'.htb)
      expect(s.find_and_delete(d)).to eq(Bitcoin::Script.new)

      s = Bitcoin::Script.parse_from_payload('0302ff030302ff03'.htb)
      d = Bitcoin::Script.parse_from_payload('02'.htb)
      expect(s.find_and_delete(d)).to eq(s) # find_and_delete matches entire opcodes

      s = Bitcoin::Script.parse_from_payload('0302ff030302ff03'.htb)
      d = Bitcoin::Script.parse_from_payload('ff'.htb)
      expect(s.find_and_delete(d)).to eq(s)

      # This is an odd edge case: strip of the push-three-bytes prefix, leaving 02ff03 which is push-two-bytes:
      s = Bitcoin::Script.parse_from_payload('0302ff030302ff03'.htb)
      d = Bitcoin::Script.parse_from_payload('03'.htb)
      expect(s.find_and_delete(d)).to eq(Bitcoin::Script.new << 'ff03' << 'ff03')

      # Byte sequence that spans multiple opcodes:
      s = Bitcoin::Script.parse_from_payload('02feed5169'.htb) # PUSH(0xfeed) OP_1 OP_VERIFY
      d = Bitcoin::Script.parse_from_payload('feed51'.htb)
      expect(s.find_and_delete(d)).to eq(s) # doesn't match 'inside' opcodes

      s = Bitcoin::Script.parse_from_payload('02feed5169'.htb) # PUSH(0xfeed) OP_1 OP_VERIFY
      d = Bitcoin::Script.parse_from_payload('02feed51'.htb)
      expect(s.find_and_delete(d)).to eq(Bitcoin::Script.parse_from_payload('69'.htb))

      s = Bitcoin::Script.parse_from_payload('516902feed5169'.htb)
      d = Bitcoin::Script.parse_from_payload('feed51'.htb)
      expect(s.find_and_delete(d)).to eq(s)

      s = Bitcoin::Script.parse_from_payload('516902feed5169'.htb) # PUSH(0xfeed) OP_1 OP_VERIFY
      d = Bitcoin::Script.parse_from_payload('02feed51'.htb)
      expect(s.find_and_delete(d)).to eq(Bitcoin::Script.parse_from_payload('516969'.htb))

      s = Bitcoin::Script.new << OP_0 << OP_0 << OP_1 << OP_1
      d = Bitcoin::Script.new << OP_0 << OP_1
      expect(s.find_and_delete(d)).to eq(Bitcoin::Script.new << OP_0 << OP_1)

      s = Bitcoin::Script.new << OP_0 << OP_0 << OP_1 << OP_0 << OP_1 << OP_1
      d = Bitcoin::Script.new << OP_0 << OP_1
      expect(s.find_and_delete(d)).to eq(Bitcoin::Script.new << OP_0 << OP_1)

      s = Bitcoin::Script.parse_from_payload('0003feed'.htb)
      d = Bitcoin::Script.parse_from_payload('03feed'.htb)
      expect(s.find_and_delete(d)).to eq(Bitcoin::Script.parse_from_payload('00'.htb))

      s = Bitcoin::Script.parse_from_payload('0003feed'.htb)
      d = Bitcoin::Script.parse_from_payload('00'.htb)
      expect(s.find_and_delete(d)).to eq(Bitcoin::Script.parse_from_payload('03feed'.htb))
    end
  end

  describe '#delete_opcode' do
    it 'should be delete target opcode' do
      script = Bitcoin::Script.from_string('038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 OP_CHECKSIGVERIFY OP_CODESEPARATOR 038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 OP_CHECKSIGVERIFY OP_CODESEPARATOR 1')
      expect(script.delete_opcode(Bitcoin::Opcodes::OP_CODESEPARATOR).to_s).to eq('038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 OP_CHECKSIGVERIFY 038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 OP_CHECKSIGVERIFY 1')
    end
  end

  describe '#witness_commitment' do
    context 'has commitment' do
      subject {Bitcoin::Script.parse_from_payload('6a24aa21a9ed670436c55de638c8100326d72998157a61aab2af1a8d4c5785f9093134b78e33'.htb)}
      it 'should be return commitment hash' do
        expect(subject.witness_commitment).to eq('670436c55de638c8100326d72998157a61aab2af1a8d4c5785f9093134b78e33')
      end
    end

    context 'invalid commitment' do
      it 'should be return nil' do
        # push data only
        script = Bitcoin::Script.parse_from_payload('24aa21a9ed670436c55de638c8100326d72998157a61aab2af1a8d4c5785f9093134b78e33'.htb)
        expect(script.witness_commitment).to be nil
        # invalid commitment header
        script = Bitcoin::Script.parse_from_payload('6a24aa21a9ee670436c55de638c8100326d72998157a61aab2af1a8d4c5785f9093134b78e33'.htb)
        expect(script.witness_commitment).to be nil
        # invalid commitment hash length
        script = Bitcoin::Script.parse_from_payload('6a24aa21a9ed670436c55de638c8100326d72998157a61aab2af1a8d4c5785f9093134b78e'.htb)
        expect(script.witness_commitment).to be nil
      end
    end
  end

end
