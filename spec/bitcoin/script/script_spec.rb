require 'spec_helper'
include Bitcoin::Opcodes

describe Bitcoin::Script do

  describe '#append_data' do
    context 'data < 0xff' do
      subject { Bitcoin::Script.new << 'foo' }
      it 'should be append' do
        expect(subject.to_hex).to eq('02f880')
      end
    end
    context '0xff < data < 0xffff' do
      subject { Bitcoin::Script.new << 'f' * 256 }
      it 'should be append' do
        expect(subject.to_hex).to eq('4c80ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
      end
    end
    context 'int value include' do
      it 'should be append' do
        s = Bitcoin::Script.new << OP_1NEGATE << Bitcoin::Script.encode_number(1000) << OP_ADD
        expect(s.to_hex).to eq('4f02e80393')
        expect(s.to_s).to eq('OP_1NEGATE 1000 OP_ADD')
        s = Bitcoin::Script.new << OP_1NEGATE << Bitcoin::Script.encode_number(100) << OP_ADD
        expect(s.to_hex).to eq('4f016493')
        # negative value
        s = Bitcoin::Script.new << OP_1NEGATE << Bitcoin::Script.encode_number(-1000) << OP_ADD
        expect(s.to_hex).to eq('4f02e88393')
        expect(s.to_s).to eq('OP_1NEGATE -1000 OP_ADD')
      end
    end
    context 'binary and hex mixed' do
      it 'should be append as same data' do
        hex = 'f9fc751cb7dc372406a9f8d738d5e6f8f63bab71986a39cf36ee70ee17036d07'
        expect(Bitcoin::Script.new << hex).to eq(Bitcoin::Script.new << hex.htb)
      end
    end
  end

  describe 'p2pk script' do
    subject {
      Bitcoin::Script.new << '032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35' << OP_CHECKSIG
    }
    it 'should be p2pk' do
      expect(subject.get_pubkeys).to eq(['032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35'])
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
        expect(subject.p2tr?).to be false
        expect(subject.p2a?).to be false
        expect(subject.multisig?).to be false
        expect(subject.op_return?).to be false
        expect(subject.standard?).to be true
        expect(subject.p2pk?).to be false
        expect(subject.to_addr).to eq('17T9tBC2dSpusL1rhT4T4AV4if963Tpfym')
        expect(subject.get_pubkeys).to eq([])
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
        expect(subject.p2tr?).to be false
        expect(subject.p2a?).to be false
        expect(subject.multisig?).to be false
        expect(subject.op_return?).to be false
        expect(subject.standard?).to be true
        expect(subject.p2pk?).to be false
        expect(subject.to_addr).to eq('bc1qgmp0h7lvexdxx9y05pmdukx09xcteu9svvvxlw')
        expect(subject.get_pubkeys).to eq([])
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
        expect(subject[0].to_hex).to eq('a9147620a79e8657d066cff10e21228bf983cf546ac687')
        expect(subject[0].to_s).to eq('OP_HASH160 7620a79e8657d066cff10e21228bf983cf546ac6 OP_EQUAL')
        expect(subject[0].p2pkh?).to be false
        expect(subject[0].p2sh?).to be true
        expect(subject[0].p2wpkh?).to be false
        expect(subject[0].p2wsh?).to be false
        expect(subject[0].p2tr?).to be false
        expect(subject[0].p2a?).to be false
        expect(subject[0].multisig?).to be false
        expect(subject[0].op_return?).to be false
        expect(subject[0].standard?).to be true
        expect(subject[0].p2pk?).to be false
        expect(subject[0].to_addr).to eq('3CTcn59uJ89wCsQbeiy8AGLydXE9mh6Yrr')
        expect(subject[1].to_hex).to eq('5121021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e921032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e3552ae')
        expect(subject[1].to_s).to eq('1 021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9 032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35 2 OP_CHECKMULTISIG')
        expect(subject[1].to_addr).to be nil
        expect(subject[0].get_pubkeys).to eq([])
      end
    end

    context 'testnet' do
      it 'should be generate P2SH script' do
        expect(subject[0].to_addr).to eq('2N41pqp5vuafHQf39KraznDLEqsSKaKmrij')
        expect(subject[1].to_addr).to be nil
      end
    end

    context 'invalid script length' do
      it 'should raise error' do
        boundary = Bitcoin::Script.new
        520.times { boundary << OP_0 }
        expect{ boundary.to_p2sh }.not_to raise_error
        boundary << OP_0
        expect{ boundary.to_p2sh }.to raise_error(RuntimeError)
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
        expect(subject.to_hex).to eq('00203ce1c71303e564430e0c5721727739290046302a9674f1d67a249cfd2ce7d3fd')
        expect(subject.to_s).to eq('0 3ce1c71303e564430e0c5721727739290046302a9674f1d67a249cfd2ce7d3fd')
        expect(subject.p2pkh?).to be false
        expect(subject.p2sh?).to be false
        expect(subject.p2wpkh?).to be false
        expect(subject.p2wsh?).to be true
        expect(subject.p2tr?).to be false
        expect(subject.p2a?).to be false
        expect(subject.multisig?).to be false
        expect(subject.op_return?).to be false
        expect(subject.standard?).to be true
        expect(subject.p2pk?).to be false
        expect(subject.to_addr).to eq('bc1q8nsuwycru4jyxrsv2ushyaee9yqyvvp2je60r4n6yjw06t88607s264w7g')
        expect(subject.get_pubkeys).to eq([])
      end
    end

    context 'testnet' do
      it 'should be generate P2WSH script' do
        expect(subject.to_addr).to eq('tb1q8nsuwycru4jyxrsv2ushyaee9yqyvvp2je60r4n6yjw06t88607sajrpy8')
      end
    end

    context 'invalid script length' do
      it 'should raise error' do
        boundary = Bitcoin::Script.new
        10_000.times { boundary << OP_0 }
        expect{ Bitcoin::Script.to_p2wsh(boundary) }.not_to raise_error
        boundary << OP_0
        expect{ Bitcoin::Script.to_p2wsh(boundary) }.to raise_error(ArgumentError)
      end
    end
  end

  describe 'P2TR script' do
    subject { Bitcoin::Script.to_p2tr('a0d0c06640b95b78f965416ad6971b3b1609c3cd9b512aaa39439088211868b7')}
    it 'should be p2tr', network: :mainnet do
      expect(subject.p2pkh?).to be false
      expect(subject.p2sh?).to be false
      expect(subject.p2wpkh?).to be false
      expect(subject.p2wsh?).to be false
      expect(subject.p2tr?).to be true
      expect(subject.p2a?).to be false
      expect(subject.multisig?).to be false
      expect(subject.op_return?).to be false
      expect(subject.standard?).to be true
      expect(subject.p2pk?).to be false
      expect(subject.to_addr).to eq('bc1p5rgvqejqh9dh37t9g94dd9cm8vtqns7dndgj423egwggsggcdzmsspvr7j')
      expect(subject.type).to eq('witness_v1_taproot')
    end

    context 'invalid P2TR' do
      it 'raise ArgumentError' do
        expect{Bitcoin::Script.to_p2tr('03a0d0c06640b95b78f965416ad6971b3b1609c3cd9b512aaa39439088211868b7')}.to raise_error(ArgumentError, 'Invalid public key size')
      end
    end
  end

  describe 'P2A script' do
    subject { Bitcoin::Script.to_p2a}
    it 'should be p2tr', network: :mainnet do
      expect(subject.p2pkh?).to be false
      expect(subject.p2sh?).to be false
      expect(subject.p2wpkh?).to be false
      expect(subject.p2wsh?).to be false
      expect(subject.p2tr?).to be false
      expect(subject.p2a?).to be true
      expect(subject.multisig?).to be false
      expect(subject.op_return?).to be false
      expect(subject.standard?).to be true
      expect(subject.p2pk?).to be false
      expect(subject.to_addr).to eq('bc1pfeessrawgf')
      expect(subject.type).to eq('anchor')
      expect(subject.witness_program?).to be true
    end
  end

  describe 'P2PK script' do
    subject { Bitcoin::Script.new << '032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35' << OP_CHECKSIG }
    it ' should be p2pk' do
      expect(subject.p2pkh?).to be false
      expect(subject.p2sh?).to be false
      expect(subject.p2wpkh?).to be false
      expect(subject.p2wsh?).to be false
      expect(subject.p2tr?).to be false
      expect(subject.p2a?).to be false
      expect(subject.multisig?).to be false
      expect(subject.op_return?).to be false
      expect(subject.standard?).to be false
      expect(subject.p2pk?).to be true
      expect(subject.to_addr).to be nil
    end
  end

  describe 'multisig script' do
    context 'valid multsig' do
      subject {
        k1 = '021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9'
        k2 = '032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35'
        Bitcoin::Script.to_multisig_script(2, [k1, k2])
      }
      it 'should treat as multisig' do
        expect(subject.p2pkh?).to be false
        expect(subject.p2sh?).to be false
        expect(subject.p2wpkh?).to be false
        expect(subject.p2wsh?).to be false
        expect(subject.p2tr?).to be false
        expect(subject.p2a?).to be false
        expect(subject.multisig?).to be true
        expect(subject.op_return?).to be false
        expect(subject.standard?).to be true
        expect(subject.p2pk?).to be false
        expect(subject.to_addr).to be nil
        expect(subject.get_pubkeys).to eq(['021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9', '032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35'])
      end
    end

    context 'invalid multisig' do
      it 'should be false' do
        # 2bb7e8720356f79a9005488a529ab12d6f516879b2357224204cb5f2b780fd02:0
        script = Bitcoin::Script.parse_from_payload('402153484f55544f555420544f2023424954434f494e2d4153534554532020202020202020202020202020202020202020202020202020202020202020202020207551210391b373843e77f5ac1f05db4afb5151190e67cfee5a48f7925d71da7c5e91942251ae'.htb)
        expect(script.multisig?).to be false
      end
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
        expect(subject.p2tr?).to be false
        expect(subject.p2a?).to be false
        expect(subject.multisig?).to be false
        expect(subject.op_return?).to be true
        expect(subject.standard?).to be true
        expect(subject.p2pk?).to be false
        expect(subject.op_return_data.bth).to eq('04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef3804678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38')
        expect(subject.get_pubkeys).to eq([])
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

    context 'no op_return data' do
      subject {
        Bitcoin::Script.new << OP_RETURN
      }
      it 'should correct op_return and no data' do
        expect(subject.op_return?).to be true
        expect(subject.op_return_data).to be nil
      end
    end
  end

  describe 'parse from payload' do
    context 'spendable' do
      subject { Bitcoin::Script.parse_from_payload('76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac'.htb) }
      it 'should be parsed' do
        expect(subject.to_s).to eq('OP_DUP OP_HASH160 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0 OP_EQUALVERIFY OP_CHECKSIG')
        expect(subject.p2pkh?).to be true
      end
    end

    context 'unspendable' do
      subject { Bitcoin::Script.parse_from_payload('76a914c486de584a735ec2f22da7cd9681614681f92173d83d0aa68688ac'.htb) }
      it 'should be parsed' do
        expect(subject.to_hex).to eq('76a914c486de584a735ec2f22da7cd9681614681f92173d83d0aa68688ac')
        expect(subject.p2pkh?).to be false
        expect(subject.to_s).to eq('OP_DUP OP_HASH160 c486de584a735ec2f22da7cd9681614681f92173 OP_UNKNOWN [error]')
        # no push data
        s = Bitcoin::Script.parse_from_payload('614c'.htb) # OP_NOP OP_PUSHDATA1
        expect(s.to_hex).to eq('614c')
        expect(s.to_s).to eq('OP_NOP 4c')
      end
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

      contract = Bitcoin::Script.from_string('OP_HASH160 b6ca66aa538d28518852b2104d01b8b499fc9b23 OP_EQUAL OP_IF 021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9 OP_ELSE 1000 OP_CHECKSEQUENCEVERIFY OP_DROP 032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35 OP_ENDIF OP_CHECKSIG')
      expect(contract.to_hex).to eq('a914b6ca66aa538d28518852b2104d01b8b499fc9b23876321021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e96702e803b27521032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e3568ac')
      expect(contract.to_s).to eq('OP_HASH160 b6ca66aa538d28518852b2104d01b8b499fc9b23 OP_EQUAL OP_IF 021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e9 OP_ELSE 1000 OP_CSV OP_DROP 032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35 OP_ENDIF OP_CHECKSIG')
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
      expect(Bitcoin::Script.from_string('0000 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d').witness_program?).to be true
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

  describe '#parse_from_addr' do
    context 'mainnet', network: :mainnet do
      it 'should generate script' do
        # P2PKH
        expect(Bitcoin::Script.parse_from_addr('191arn68nSLRiNJXD8srnmw4bRykBkVv6o')).to eq(Bitcoin::Script.parse_from_payload('76a91457dd450aed53d4e35d3555a24ae7dbf3e08a78ec88ac'.htb))
        # P2SH
        expect(Bitcoin::Script.parse_from_addr('3HG15Tn6hEd1WVR1ySQtWRstTbvyy6B5V8')).to eq(Bitcoin::Script.parse_from_payload('a914aac6e837af9eba6951552e83862740b069cf59f587'.htb))
        # P2WPKH
        expect(Bitcoin::Script.parse_from_addr('bc1q2lw52zhd202wxhf42k3y4e7m70sg578ver73dn')).to eq(Bitcoin::Script.from_string('0 57dd450aed53d4e35d3555a24ae7dbf3e08a78ec'))
        # P2WSH
        expect(Bitcoin::Script.parse_from_addr('bc1q8nsuwycru4jyxrsv2ushyaee9yqyvvp2je60r4n6yjw06t88607s264w7g')).to eq(Bitcoin::Script.from_string('0 3ce1c71303e564430e0c5721727739290046302a9674f1d67a249cfd2ce7d3fd'))
      end
    end

    context 'testnet' do
      it 'should generate script' do
        # P2PKH
        expect(Bitcoin::Script.parse_from_addr('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F1')).to eq(Bitcoin::Script.parse_from_payload('76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac'.htb))
        # P2SH
        expect(Bitcoin::Script.parse_from_addr('2N3wh1eYqMeqoLxuKFv8PBsYR4f8gYn8dHm')).to eq(Bitcoin::Script.parse_from_payload('a914755874542a017c665184c356f67c20cf4a0621ca87'.htb))
        # P2WPKH
        expect(Bitcoin::Script.parse_from_addr('tb1qgmp0h7lvexdxx9y05pmdukx09xcteu9sx2h4ya')).to eq(Bitcoin::Script.from_string('0 46c2fbfbecc99a63148fa076de58cf29b0bcf0b0'))
        # P2WSH
        expect(Bitcoin::Script.parse_from_addr('tb1q8nsuwycru4jyxrsv2ushyaee9yqyvvp2je60r4n6yjw06t88607sajrpy8')).to eq(Bitcoin::Script.from_string('0 3ce1c71303e564430e0c5721727739290046302a9674f1d67a249cfd2ce7d3fd'))
      end
    end

    context 'invalid address' do
      it 'should raise error' do
        expect{Bitcoin::Script.parse_from_addr('191arn68nSLRiNJXD8srnmw4bRykBkVv6o')}.to raise_error(ArgumentError, 'Invalid address.')
        expect{Bitcoin::Script.parse_from_addr('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F2')}.to raise_error(ArgumentError, 'Invalid address.')
        expect{Bitcoin::Script.parse_from_addr('bc1q2lw52zhd202wxhf42k3y4e7m70sg578ver73dn')}.to raise_error(ArgumentError, 'Invalid address.')
        expect{Bitcoin::Script.parse_from_addr('tb1q8nsuwycru4jyxrsv2ushyaee9yqyvvp2je60r4n6yjw06t88607sajrpy0')}.to raise_error(ArgumentError, 'Invalid address.')
      end
    end
  end

  describe '#include?' do
    it 'should be judge' do
      # P2PKH
      p2pkh = Bitcoin::Script.parse_from_payload('76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac'.htb)
      pubkey_hash = '46c2fbfbecc99a63148fa076de58cf29b0bcf0b0'
      expect(p2pkh.include?(pubkey_hash)).to be true
      expect(p2pkh.include?(pubkey_hash.htb)).to be true
      expect(p2pkh.include?('46c2fbfbecc99a63148fa076de58cf29b0bcf0b1')).to be false
      expect(p2pkh.include?(OP_EQUALVERIFY)).to be true
      expect(p2pkh.include?(OP_EQUAL)).to be false
      # multisig
      multisig = Bitcoin::Script.parse_from_payload('5121021525ca2c0cbd42de7e4f5793c79887fbc8b136b5fe98b279581ef6959307f9e921032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e3552ae'.htb)
      expect(multisig.include?(OP_1)).to be true
      expect(multisig.include?(OP_3)).to be false
      expect(multisig.include?('032ad705d98318241852ba9394a90e85f6afc8f7b5f445675040318a9d9ea29e35')).to be true
    end
  end

  describe '#run' do
    context 'valid script' do
      subject {Bitcoin::Script.from_string('6 1 OP_ADD 7 OP_EQUAL')}
      it 'should return true.' do
        expect(subject.run).to be true
      end
    end

    context 'invalid script' do
      subject {Bitcoin::Script.from_string('3 1 OP_ADD 7 OP_EQUAL')}
      it 'should return false.' do
        expect(subject.run).to be false
      end
    end
  end

end
