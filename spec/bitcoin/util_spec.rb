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
    end

    it 'should pack boolean' do
      expect(util.pack_boolean(true)).to eq([0xff].pack('C'))
      expect(util.pack_boolean(false)).to eq([0x00].pack('C'))
    end

    it 'should unpack boolean' do
      expect(util.unpack_boolean([0xff].pack('C')).first).to be true
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
      util.encode_base58_address(version + hash160)
    }
    it 'should be encoded' do
      expect(subject).to eq('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F1')
    end
  end


end
