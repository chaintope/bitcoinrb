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

  describe '#derive' do
    subject { test_master_key }
    it 'should derive child key using path.' do
      expect(subject.derive("m/84'/0'/0'/0/0").to_base58).to eq('vprv9PCKRBonACARg64Rx5BeQTTf2ed93rAEFDGHTq9RjYVuFSWvrWj79AV5ChNVYix78vxRqBwCZJZfwCMdkmteMvEgiHwyyzcRmLXkPo5XYwk')
      expect(subject.derive("m/84'/0'/0'/0/1").to_base58).to eq('vprv9PCKRBonACARiWy39ictxyUemkpjA3cSbBZk8DXmnXA6x4kL3MbYEa5B3RtZPWmaFWSq4gm5dUrPUFzQQZbvpHBkyTxpvvAW5SNj6hz6pis')
      expect(subject.derive("m/84'/0'/0'/1/0").to_base58).to eq('vprv9Pya2CbyhNznX7qBV62k8U9Wn3gKLGy1KaUPzeC9Poxb626Xou2nD7HfseF4EraidCSvQxQffEcNBmwWJmi8Gi4J3aCqg4EKZkX8fayvUR3')
      expect(subject.derive("m/44'/0'/0/0'/1").to_base58).to eq('tprv8jHdTXw5rTbS9qPSSP9vjK2aoqSrowGxnG4bK6iMiKt1tiYxyi6QXwiqcn6t4xBSgZHsgKjremtm3FxGDpR6cUVNDhdT9QJ6dJdGUXarVU6')
      expect(subject.derive("m/44'/1/0'/0/1'").to_base58).to eq('tprv8juQXKssHqHuEemMuTBgxh2PSwuK3GoCBTAdnSwkG9bYkTJTS1G1Vqne7NVE9maP7hV177CT7Nqn1dC95331pKswEkvXdErBgDKBs518HcN')

      expect{subject.derive("n/44'/1/0'/0/1'")}.to raise_error(ArgumentError)
      expect{subject.derive("m/m'/1/0'/0/1'")}.to raise_error(ArgumentError)
      expect{subject.derive("m/44'/m/0'/0/1'")}.to raise_error(ArgumentError)
      expect{subject.derive("m/44'/1/0'/0/1m'")}.to raise_error(ArgumentError)

    end
  end

end
