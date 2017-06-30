require 'spec_helper'

describe Bitcoin::Opcodes do

  describe 'convert opcode to name' do
    it 'should be convert' do
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_DROP)).to eq('OP_DROP')
    end
  end

  describe 'convert name to opcode' do
    it 'should be convert' do
      expect(Bitcoin::Opcodes.name_to_opcode('OP_DROP')).to eq(Bitcoin::Opcodes::OP_DROP)
    end
  end

end