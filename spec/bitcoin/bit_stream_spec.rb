require 'spec_helper'

describe 'Bitcoin::BitStream' do

  describe 'reader and writer' do
    it 'should be read and write' do
      writer = Bitcoin::BitStreamWriter.new
      writer.write(0, 1)
      writer.write(2, 2)
      writer.write(6, 3)
      writer.write(11, 4)
      writer.write(1, 5)
      writer.write(32, 6)
      writer.write(7, 7)
      writer.write(30497, 16)
      writer.flush
      serialize_int1 = writer.stream[0..3].unpack("I").first
      serialize_int2 = writer.stream[4..-1].reverse.bth.to_i(16)
      expect(serialize_int1).to eq(0x7700C35A)
      expect(serialize_int2).to eq(0x1072)

      reader = Bitcoin::BitStreamReader.new(writer.stream)
      expect(reader.read(1)).to eq(0)
      expect(reader.read(2)).to eq(2)
      expect(reader.read(3)).to eq(6)
      expect(reader.read(4)).to eq(11)
      expect(reader.read(5)).to eq(1)
      expect(reader.read(6)).to eq(32)
      expect(reader.read(7)).to eq(7)
      expect(reader.read(16)).to eq(30497)
      expect{reader.read(8)}.to raise_error(IOError)
    end
  end

end