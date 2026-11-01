require 'spec_helper'

describe Bitcoin::KeyPath do

  let(:test_class) { Struct.new(:key_path) { include Bitcoin::KeyPath } }
  let(:key_path) { test_class.new }

  describe "parse_key_path" do
    context 'valid path' do
      it 'should not raise error.' do
        expect{key_path.parse_key_path("m/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1")}.not_to raise_error
        expect{key_path.parse_key_path("m/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1'/1")}.not_to raise_error
        expect{key_path.parse_key_path("m/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/")}.not_to raise_error
        expect{key_path.parse_key_path("m/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1'/")}.not_to raise_error
        expect{key_path.parse_key_path("m/")}.not_to raise_error
        expect{key_path.parse_key_path("m/0")}.not_to raise_error
        expect{key_path.parse_key_path("m/0000'/0000'/0000'")}.not_to raise_error
        expect{key_path.parse_key_path("m/01234")}.not_to raise_error
        expect{key_path.parse_key_path("m/1")}.not_to raise_error
        expect{key_path.parse_key_path("m/42")}.not_to raise_error
        expect{key_path.parse_key_path("m/4294967295")}.not_to raise_error
        expect{key_path.parse_key_path("m")}.not_to raise_error
        expect{key_path.parse_key_path("m/")}.not_to raise_error
        expect{key_path.parse_key_path("m/0")}.not_to raise_error
        expect{key_path.parse_key_path("m/0'")}.not_to raise_error
        expect{key_path.parse_key_path("m/0'/0'")}.not_to raise_error
        expect{key_path.parse_key_path("m/0/0")}.not_to raise_error
        expect{key_path.parse_key_path("m/0/0/00")}.not_to raise_error
        expect{key_path.parse_key_path("m/0/0/000000000000000000000000000000000000000000000000000000000000000000000000000000000000")}.not_to raise_error
        expect{key_path.parse_key_path("m/0/00/0")}.not_to raise_error
        expect{key_path.parse_key_path("m/1/")}.not_to raise_error
        expect{key_path.parse_key_path("m/0/4294967295")}.not_to raise_error
        expect{key_path.parse_key_path("m/4294967295")}.not_to raise_error
      end

      it 'should read a trailing h as the hardened marker, like a trailing apostrophe' do
        expect(key_path.parse_key_path("m/0h")).to eq([2147483648])
        expect(key_path.parse_key_path("m/0h/1h/2h")).to eq([2147483648, 2147483649, 2147483650])
        expect(key_path.parse_key_path("m/0'/1h/2")).to eq(key_path.parse_key_path("m/0h/1'/2"))
        expect(key_path.parse_key_path("m/2147483647h")).to eq([4294967295])
        expect{key_path.parse_key_path("m/0hh")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m/0H")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m/0'h")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m/h")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m/2147483648h")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m/2147483648'")}.to raise_error(ArgumentError, 'Invalid path.')
      end
    end

    context 'invalid path' do
      it 'should raise error.' do
        expect{key_path.parse_key_path("1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1/1")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m///////////////////////////")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m//////////////////////////'/")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m1///////////////////////////")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m1/'//////////////////////////")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path(" ")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("O")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m/0000,/0000,/0000,")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m/0x1234")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path(" 1")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m42")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m/4294967296")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("n")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("n/")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("n/0")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m/0''")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m/'0/0'")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("n/0/0")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m/0/0/f00")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m/1/1/111111111111111111111111111111111111111111111111111111111111111111111111111111111111")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m/0'/00/'0")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m/1//")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m/0/4294967296")}.to raise_error(ArgumentError, 'Invalid path.')
        expect{key_path.parse_key_path("m/4294967296")}.to raise_error(ArgumentError, 'Invalid path.')
      end
    end
  end

end