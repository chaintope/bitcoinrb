require 'spec_helper'

describe Bitcoin::Util do

  let(:test_class) { Struct.new(:util) { include Bitcoin::Util } }
  let(:util) { test_class.new }

  describe 'pack and unpack' do
    it 'should pack var string' do
      expect(util.pack_var_string('hoge')).to eq("\x04hoge")
    end

    it 'should unpack var string' do
      expect(util.unpack_var_string("\x04hoge").first).to eq('hoge')
    end

    it 'should pack var int' do
      expect(util.pack_var_int(4)).to eq([0x04].pack('C'))
      expect(util.pack_var_int(252)).to eq([0xfc].pack('C'))
      expect(util.pack_var_int(253)).to eq([0xfd, 0xfd, 0x00].pack('C*'))
      expect(util.pack_var_int(65535)).to eq([0xfd, 0xff, 0xff].pack('C*'))
      expect(util.pack_var_int(65536)).to eq([0xfe, 0x00, 0x00, 0x01, 0x00].pack('C*'))
    end

    it 'should unpack var int' do
      expect(util.unpack_var_int([0x04].pack('C')).first).to eq(4)
      expect(util.unpack_var_int([0xfc].pack('C')).first).to eq(252)
      expect(util.unpack_var_int([0xfd, 0xfd, 0x00].pack('C*')).first).to eq(253)
      expect(util.unpack_var_int([0xfd, 0xff, 0xff].pack('C*')).first).to eq(65535)
      expect(util.unpack_var_int([0xfe, 0x00, 0x00, 0x01, 0x00].pack('C*')).first).to eq(65536)
      expect(util.unpack_var_int([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff].pack('C*')).first).to eq(0xffffffffffffffff)
      expect(util.unpack_var_int([0xff].pack('C*')).first).to be_nil
      expect(util.unpack_var_int('').first).to be_nil
    end

    it 'should unpack var int from io' do
      expect(util.unpack_var_int_from_io(StringIO.new([0x04].pack('C')))).to eq(4)
      expect(util.unpack_var_int_from_io(StringIO.new([0xfc].pack('C')))).to eq(252)
      expect(util.unpack_var_int_from_io(StringIO.new([0xfd, 0xfd, 0x00].pack('C*')))).to eq(253)
      expect(util.unpack_var_int_from_io(StringIO.new([0xfd, 0xff, 0xff].pack('C*')))).to eq(65535)
      expect(util.unpack_var_int_from_io(StringIO.new([0xfe, 0x00, 0x00, 0x01, 0x00].pack('C*')))).to eq(65536)
      expect(util.unpack_var_int_from_io(StringIO.new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff].pack('C*')))).to eq(0xffffffffffffffff)
      expect(util.unpack_var_int_from_io(StringIO.new([0xff].pack('C*')))).to be_nil
      expect(util.unpack_var_int_from_io(StringIO.new)).to be_nil
    end

    it 'should pack boolean' do
      expect(util.pack_boolean(true)).to eq([0x01].pack('C'))
      expect(util.pack_boolean(false)).to eq([0x00].pack('C'))
    end

    it 'should unpack boolean' do
      expect(util.unpack_boolean([0x01].pack('C')).first).to be true
      expect(util.unpack_boolean([0x00].pack('C')).first).to be false
    end
  end

  describe '#byte_to_bit' do
    it 'should convert byte to bit' do
      expect(util.byte_to_bit('b50f'.htb)).to eq('1010110111110000')
      expect(util.byte_to_bit('5f1f00'.htb)).to eq('111110101111100000000000')
    end
  end

  describe '#hash160' do
    it 'should be hashed' do
      expect(util.hash160('0292ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c9')).to eq('46c2fbfbecc99a63148fa076de58cf29b0bcf0b0')
    end
  end

  describe '#encode_base58_address' do
    subject {
      hash160 = '46c2fbfbecc99a63148fa076de58cf29b0bcf0b0'
      version = '6f'
      util.encode_base58_address(hash160, version)
    }
    it 'should be encoded' do
      expect(subject).to eq('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F1')
    end
  end

  describe '#decode_base58_address' do
    subject {
      util.decode_base58_address('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F1')
    }
    it 'should be encoded' do
      expect(subject[0]).to eq('46c2fbfbecc99a63148fa076de58cf29b0bcf0b0')
      expect(subject[1]).to eq('6f')
    end
  end

  describe '#valid_address' do
    context 'mainnet', network: :mainnet do
      it 'should judge addoress format.' do
        expect(util.valid_address?('191arn68nSLRiNJXD8srnmw4bRykBkVv6o')).to be true
        expect(util.valid_address?('3HG15Tn6hEd1WVR1ySQtWRstTbvyy6B5V8')).to be true
        expect(util.valid_address?('bc1q2lw52zhd202wxhf42k3y4e7m70sg578ver73dn')).to be true
        expect(util.valid_address?('bc1q8nsuwycru4jyxrsv2ushyaee9yqyvvp2je60r4n6yjw06t88607s264w7g')).to be true

        expect(util.valid_address?('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F1')).to be false
        expect(util.valid_address?('2N3wh1eYqMeqoLxuKFv8PBsYR4f8gYn8dHm')).to be false
        expect(util.valid_address?('tb1qgmp0h7lvexdxx9y05pmdukx09xcteu9sx2h4ya')).to be false
        expect(util.valid_address?('tb1q8nsuwycru4jyxrsv2ushyaee9yqyvvp2je60r4n6yjw06t88607sajrpy8')).to be false

        # segwit version 1
        expect(util.valid_address?('bc1qgmp0h7lvexdxx9y05pmdukx09xcteu9svvvxlw')).to be true
      end
    end

    context 'testnet', network: :testnet do
      it 'should judge address format.' do
        expect(util.valid_address?('191arn68nSLRiNJXD8srnmw4bRykBkVv6o')).to be false
        expect(util.valid_address?('3HG15Tn6hEd1WVR1ySQtWRstTbvyy6B5V8')).to be false
        expect(util.valid_address?('bc1q2lw52zhd202wxhf42k3y4e7m70sg578ver73dn')).to be false
        expect(util.valid_address?('bc1q8nsuwycru4jyxrsv2ushyaee9yqyvvp2je60r4n6yjw06t88607s264w7g')).to be false

        expect(util.valid_address?('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F1')).to be true
        expect(util.valid_address?('2N3wh1eYqMeqoLxuKFv8PBsYR4f8gYn8dHm')).to be true
        expect(util.valid_address?('tb1qgmp0h7lvexdxx9y05pmdukx09xcteu9sx2h4ya')).to be true
        expect(util.valid_address?('tb1q8nsuwycru4jyxrsv2ushyaee9yqyvvp2je60r4n6yjw06t88607sajrpy8')).to be true

        # segwit version 1
        expect(util.valid_address?('tb1qgmp0h7lvexdxx9y05pmdukx09xcteu9sx2h4ya')).to be true
      end
    end
  end

end
