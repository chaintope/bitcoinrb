require 'spec_helper'

describe Bitcoin::Message::Inventory do

  describe 'parse payload' do
    context 'tx payload' do
      subject {
        Bitcoin::Message::Inventory.parse_from_payload('01000000cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab'.htb)
      }
      it 'should be parsed' do
        expect(subject.identifier).to eq(Bitcoin::Message::Inventory::MSG_TX)
        expect(subject.hash).to eq('cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab')
      end
    end

    context 'block payload' do
      subject {
        Bitcoin::Message::Inventory.parse_from_payload('02000000cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab'.htb)
      }
      it 'should be parsed' do
        expect(subject.identifier).to eq(Bitcoin::Message::Inventory::MSG_BLOCK)
        expect(subject.hash).to eq('cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab')
      end
    end

    context 'wtx payload' do
      subject {
        Bitcoin::Message::Inventory.parse_from_payload('05000000cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab'.htb)
      }
      it 'should be parsed' do
        expect(subject.identifier).to eq(Bitcoin::Message::Inventory::MSG_WTX)
        expect(subject.hash).to eq('cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab')
        expect(subject.block?).to be false
        expect(subject.to_payload.bth).to eq('05000000cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab')
      end
    end

    context 'unknown identifier' do
      subject {
        Bitcoin::Message::Inventory.parse_from_payload('78563412cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab'.htb)
      }
      it 'should be parsed and kept as it is' do
        expect(subject.identifier).to eq(0x12345678)
        expect(subject.known?).to be false
        expect(subject.block?).to be false
        expect(subject.to_payload.bth).to eq('78563412cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab')
      end
    end

    context 'invalid size' do
      it 'raise error' do
        expect{ Bitcoin::Message::Inventory.parse_from_payload('01000000cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad67'.htb) }.
          to raise_error(Bitcoin::Message::Error, 'invalid inventory size.')
      end
    end
  end

  describe '#known?' do
    it 'should be true for the types this library knows' do
      Bitcoin::Message::Inventory::KNOWN_IDENTIFIERS.each do |id|
        expect(Bitcoin::Message::Inventory.new(id, 'aa' * 32).known?).to be(true), id.to_s
      end
      expect(Bitcoin::Message::Inventory.new(0, 'aa' * 32).known?).to be false
      expect(Bitcoin::Message::Inventory.new(6, 'aa' * 32).known?).to be false
    end
  end

  describe '#initialize' do
    it 'should reject an identifier which is not a 32 bit unsigned integer' do
      [-1, 2**32, '1', nil].each do |id|
        expect { Bitcoin::Message::Inventory.new(id, 'aa' * 32) }.
          to raise_error(Bitcoin::Message::Error, "invalid type identifier specified. identifier = #{id}"), id.inspect
      end
    end
  end

  describe 'to_payload' do
    subject{
      Bitcoin::Message::Inventory.new(Bitcoin::Message::Inventory::MSG_TX, 'cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab').to_payload
    }
    it 'should generate payload' do
      expect(subject.bth).to eq('01000000cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab')
    end
  end

end