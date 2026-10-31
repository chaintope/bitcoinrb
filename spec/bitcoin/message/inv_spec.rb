require 'spec_helper'

describe Bitcoin::Message::Inv do

  describe 'parse' do
    subject {
      Bitcoin::Message::Inv.parse_from_payload('0201000000099c332dc6d71c968a3f47d6ffd43436062c72dad477b515ce2e108e1e6f109601000000e6cf87650476e8677543885e388761f09c732e66d479501f9d9c19cdb2b50e05'.htb)
    }
    it do
      expect(subject.inventories.length).to eq(2)
      expect(subject.inventories[0].hash).to eq('099c332dc6d71c968a3f47d6ffd43436062c72dad477b515ce2e108e1e6f1096')
      expect(subject.inventories[0].identifier).to eq(1)
      expect(subject.inventories[1].hash).to eq('e6cf87650476e8677543885e388761f09c732e66d479501f9d9c19cdb2b50e05')
      expect(subject.inventories[1].identifier).to eq(1)
    end
  end

  describe 'to_pkt' do
    subject {
      inv = Bitcoin::Message::Inv.new
      inv.inventories << Bitcoin::Message::Inventory.new(1, '099c332dc6d71c968a3f47d6ffd43436062c72dad477b515ce2e108e1e6f1096')
      inv.inventories << Bitcoin::Message::Inventory.new(1, 'e6cf87650476e8677543885e388761f09c732e66d479501f9d9c19cdb2b50e05')
      inv.to_pkt
    }
    it do
      expect(subject.bth).to eq('0b110907696e760000000000000000004900000075a56c590201000000099c332dc6d71c968a3f47d6ffd43436062c72dad477b515ce2e108e1e6f109601000000e6cf87650476e8677543885e388761f09c732e66d479501f9d9c19cdb2b50e05')
    end
  end


  describe 'number of inventories' do
    it 'should accept 50000 and reject 50001, as Bitcoin Core does' do
      one = Bitcoin::Message::Inventory.new(1, 'aa' * 32).to_payload
      expect(Bitcoin::Message::Inv.parse_from_payload(Bitcoin.pack_var_int(50_000) + one * 50_000).inventories.size).to eq(50_000)
      expect { Bitcoin::Message::Inv.parse_from_payload(Bitcoin.pack_var_int(50_001) + one * 50_001) }.
        to raise_error(Bitcoin::Message::Error, 'inv message size 50001 exceeds 50000.')
      expect { Bitcoin::Message::GetData.parse_from_payload(Bitcoin.pack_var_int(50_001)) }.
        to raise_error(Bitcoin::Message::Error, 'getdata message size 50001 exceeds 50000.')
    end
  end
end
