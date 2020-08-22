require 'spec_helper'

describe Bitcoin::Opcodes do

  describe 'convert opcode to name' do
    it 'should be convert' do
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_DROP)).to eq('OP_DROP')
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_0)).to eq('0')
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_1)).to eq('1')
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_2)).to eq('2')
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_3)).to eq('3')
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_4)).to eq('4')
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_5)).to eq('5')
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_6)).to eq('6')
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_7)).to eq('7')
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_8)).to eq('8')
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_9)).to eq('9')
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_10)).to eq('10')
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_11)).to eq('11')
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_12)).to eq('12')
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_13)).to eq('13')
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_14)).to eq('14')
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_15)).to eq('15')
      expect(Bitcoin::Opcodes.opcode_to_name(Bitcoin::Opcodes::OP_16)).to eq('16')
    end
  end

  describe 'convert name to opcode' do
    it 'should be convert' do
      expect(Bitcoin::Opcodes.name_to_opcode('OP_DROP')).to eq(Bitcoin::Opcodes::OP_DROP)
      expect(Bitcoin::Opcodes.name_to_opcode('0')).to eq(Bitcoin::Opcodes::OP_0)
      expect(Bitcoin::Opcodes.name_to_opcode('1')).to eq(Bitcoin::Opcodes::OP_1)
      expect(Bitcoin::Opcodes.name_to_opcode('2')).to eq(Bitcoin::Opcodes::OP_2)
      expect(Bitcoin::Opcodes.name_to_opcode('3')).to eq(Bitcoin::Opcodes::OP_3)
      expect(Bitcoin::Opcodes.name_to_opcode('4')).to eq(Bitcoin::Opcodes::OP_4)
      expect(Bitcoin::Opcodes.name_to_opcode('5')).to eq(Bitcoin::Opcodes::OP_5)
      expect(Bitcoin::Opcodes.name_to_opcode('6')).to eq(Bitcoin::Opcodes::OP_6)
      expect(Bitcoin::Opcodes.name_to_opcode('7')).to eq(Bitcoin::Opcodes::OP_7)
      expect(Bitcoin::Opcodes.name_to_opcode('8')).to eq(Bitcoin::Opcodes::OP_8)
      expect(Bitcoin::Opcodes.name_to_opcode('9')).to eq(Bitcoin::Opcodes::OP_9)
      expect(Bitcoin::Opcodes.name_to_opcode('10')).to eq(Bitcoin::Opcodes::OP_10)
      expect(Bitcoin::Opcodes.name_to_opcode('11')).to eq(Bitcoin::Opcodes::OP_11)
      expect(Bitcoin::Opcodes.name_to_opcode('12')).to eq(Bitcoin::Opcodes::OP_12)
      expect(Bitcoin::Opcodes.name_to_opcode('13')).to eq(Bitcoin::Opcodes::OP_13)
      expect(Bitcoin::Opcodes.name_to_opcode('14')).to eq(Bitcoin::Opcodes::OP_14)
      expect(Bitcoin::Opcodes.name_to_opcode('15')).to eq(Bitcoin::Opcodes::OP_15)
      expect(Bitcoin::Opcodes.name_to_opcode('16')).to eq(Bitcoin::Opcodes::OP_16)
    end
  end

  describe '#defined?' do
    context 'defined' do
      it 'should be true' do
        expect(Bitcoin::Opcodes.defined?(Bitcoin::Opcodes::OP_DROP)).to be true
        expect(Bitcoin::Opcodes.defined?(0xb9.chr.opcode)).to be true
      end
    end

    context 'undefined' do
      it 'should be false' do
        expect(Bitcoin::Opcodes.defined?(0xc1.chr.opcode)).to be false
        expect(Bitcoin::Opcodes.defined?(0xfff)).to be false
        expect(Bitcoin::Opcodes.defined?(0xbb.chr.opcode)).to be false
      end
    end
  end

  describe 'op_success?' do
    context 'opcode is within range OP_SUCCESS' do
      it 'should return true.' do
        expect(Bitcoin::Opcodes.op_success?(80)).to be true
        expect(Bitcoin::Opcodes.op_success?(98)).to be true
        expect(Bitcoin::Opcodes.op_success?(126)).to be true
        expect(Bitcoin::Opcodes.op_success?(129)).to be true
        expect(Bitcoin::Opcodes.op_success?(131)).to be true
        expect(Bitcoin::Opcodes.op_success?(134)).to be true
        expect(Bitcoin::Opcodes.op_success?(137)).to be true
        expect(Bitcoin::Opcodes.op_success?(138)).to be true
        expect(Bitcoin::Opcodes.op_success?(141)).to be true
        expect(Bitcoin::Opcodes.op_success?(142)).to be true
        expect(Bitcoin::Opcodes.op_success?(149)).to be true
        expect(Bitcoin::Opcodes.op_success?(153)).to be true
        expect(Bitcoin::Opcodes.op_success?(187)).to be true
        expect(Bitcoin::Opcodes.op_success?(254)).to be true

      end
    end

    context 'opcode is outside the scope of OP_SUCCESS' do
      it 'should return false.' do
        expect(Bitcoin::Opcodes.op_success?(79)).to be false
        expect(Bitcoin::Opcodes.op_success?(81)).to be false
        expect(Bitcoin::Opcodes.op_success?(97)).to be false
        expect(Bitcoin::Opcodes.op_success?(99)).to be false
        expect(Bitcoin::Opcodes.op_success?(125)).to be false
        expect(Bitcoin::Opcodes.op_success?(130)).to be false
        expect(Bitcoin::Opcodes.op_success?(135)).to be false
        expect(Bitcoin::Opcodes.op_success?(136)).to be false
        expect(Bitcoin::Opcodes.op_success?(139)).to be false
        expect(Bitcoin::Opcodes.op_success?(140)).to be false
        expect(Bitcoin::Opcodes.op_success?(143)).to be false
        expect(Bitcoin::Opcodes.op_success?(148)).to be false
        expect(Bitcoin::Opcodes.op_success?(154)).to be false
        expect(Bitcoin::Opcodes.op_success?(186)).to be false
        expect(Bitcoin::Opcodes.op_success?(255)).to be false
      end
    end
  end

end