require 'spec_helper'

describe Bitcoin::Wallet::MasterKey do

  describe '#parse_from_payload, #to_payload' do
    subject { Bitcoin::Wallet::MasterKey.parse_from_payload('0110f9d75d45f59a9e07a7b6331a58ceedd740a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55'.htb) }
    it 'should load data' do
      expect(subject.encrypted).to be true
      expect(subject.salt).to eq('f9d75d45f59a9e07a7b6331a58ceedd7')
      expect(subject.seed).to eq('a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55')
      expect(subject.mnemonic).to be nil
      expect(subject.to_payload.bth).to eq('0110f9d75d45f59a9e07a7b6331a58ceedd740a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55')
    end
  end

  describe '#encrypt, #decrypt' do
    it 'should be process' do
      passphrase = 'hogehoge'
      key = Bitcoin::Wallet::MasterKey.new('a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55')
      expect{key.key}.not_to raise_error
      key.encrypt(passphrase)
      expect(key.seed).not_to eq('a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55')
      expect{key.key}.to raise_error('seed is encrypted. please decrypt the seed.')
      expect(key.encrypted).to be true
      expect{key.encrypt(passphrase)}.to raise_error('seed already encrypted.') # already encrypted.
      key.decrypt(passphrase)
      expect{key.key}.not_to raise_error
      expect(key.seed).to eq('a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55')
      expect(key.encrypted).to be false
      expect(key.salt).to eq('')
      expect{key.decrypt(passphrase)}.to raise_error('seed is not encrypted.') # not encrypted.
    end
  end

end
