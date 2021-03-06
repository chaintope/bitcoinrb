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

    context 'invalid identifier' do
      it 'raise error' do
        expect{ Bitcoin::Message::Inventory.parse_from_payload('04000000cbfb4ac9621ba90f7958cc8f726647105c2ece288eaa9018346639bbad6754ab') }.to raise_error(Bitcoin::Message::Error)
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