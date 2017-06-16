require 'spec_helper'

describe Bitcoin::Util do

  let(:test_class) { Struct.new(:util) { include Bitcoin::Util } }
  let(:util) { test_class.new }

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

end
