require 'spec_helper'

describe Bitcoin::Message::Inv do

  describe 'parse' do
    subject {
      Bitcoin::Message::Inv.parse_from_payload('0201000000099c332dc6d71c968a3f47d6ffd43436062c72dad477b515ce2e108e1e6f109601000000e6cf87650476e8677543885e388761f09c732e66d479501f9d9c19cdb2b50e05'.htb)
    }
    it do
      expect(subject.inventories.length).to eq(2)
      expect(subject.inventories[0].hash).to eq('96106f1e8e102ece15b577d4da722c063634d4ffd6473f8a961cd7c62d339c09')
      expect(subject.inventories[0].identifier).to eq(1)
      expect(subject.inventories[1].hash).to eq('050eb5b2cd199c9d1f5079d4662e739cf06187385e88437567e876046587cfe6')
      expect(subject.inventories[1].identifier).to eq(1)
    end
  end

  describe 'to_pkt' do
    subject {
      inv = Bitcoin::Message::Inv.new
      inv.inventories << Bitcoin::Message::Inventory.new(1, '96106f1e8e102ece15b577d4da722c063634d4ffd6473f8a961cd7c62d339c09')
      inv.inventories << Bitcoin::Message::Inventory.new(1, '050eb5b2cd199c9d1f5079d4662e739cf06187385e88437567e876046587cfe6')
      inv.to_pkt
    }
    it do
      expect(subject.bth).to eq('0b110907696e760000000000000000004900000075a56c590201000000099c332dc6d71c968a3f47d6ffd43436062c72dad477b515ce2e108e1e6f109601000000e6cf87650476e8677543885e388761f09c732e66d479501f9d9c19cdb2b50e05')
    end
  end

end