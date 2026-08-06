require 'spec_helper'

describe Bitcoin::Wallet::MasterKey do

  describe '#parse_from_payload, #to_payload' do
    subject { Bitcoin::Wallet::MasterKey.parse_from_payload('0110f9d75d45f59a9e07a7b6331a58ceedd740a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55'.htb) }
    it 'should load data' do
      expect(subject.encrypted).to be true
      expect(subject.salt).to eq('f9d75d45f59a9e07a7b6331a58ceedd7')
      expect(subject.seed).to eq('a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55')
      expect(subject.mnemonic).to be nil
      expect(subject.encryption_version).to eq(Bitcoin::Wallet::MasterKey::ENCRYPTED_V1)
      expect(subject.to_hex).to eq('0110f9d75d45f59a9e07a7b6331a58ceedd740a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55')
    end

    context 'unknown encryption version' do
      subject { Bitcoin::Wallet::MasterKey.parse_from_payload('0310f9d75d45f59a9e07a7b6331a58ceedd70100'.htb) }
      it 'should raise error' do
        expect { subject }.to raise_error('encrypted flag is invalid.')
      end
    end
  end

  describe '#encrypt, #decrypt' do
    let(:test_seed) {
      'a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55'
    }

    it 'should be process' do
      passphrase = 'hogehoge'
      key = Bitcoin::Wallet::MasterKey.new('a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55')
      expect{key.key}.not_to raise_error
      key.encrypt(passphrase)
      expect(key.seed).not_to eq('a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55')
      expect{key.key}.to raise_error('seed is encrypted. please decrypt the seed.')
      expect(key.encrypted).to be true
      expect{key.encrypt(passphrase)}.to raise_error('The wallet is already encrypted.') # already encrypted.
      key.decrypt(passphrase)
      expect{key.key}.not_to raise_error
      expect(key.seed).to eq('a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55')
      expect(key.encrypted).to be false
      expect(key.salt).to eq('')
      expect{key.decrypt(passphrase)}.to raise_error('The wallet is not encrypted.') # not encrypted.
    end

    it 'should be able to decrypt the seed restored from payload' do
      passphrase = 'hogehoge'
      seed = 'a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55'
      key = Bitcoin::Wallet::MasterKey.new(seed)
      key.encrypt(passphrase)
      restored = Bitcoin::Wallet::MasterKey.parse_from_payload(key.to_payload)
      expect(restored.encrypted).to be true
      expect(restored.salt).to eq(key.salt)
      expect(restored.seed).to eq(key.seed)
      restored.decrypt(passphrase)
      expect(restored.seed).to eq(seed)
    end

    it 'should use AES-256-GCM with an authenticated seed' do
      key = Bitcoin::Wallet::MasterKey.new(test_seed)
      key.encrypt('hogehoge')
      expect(key.encryption_version).to eq(Bitcoin::Wallet::MasterKey::ENCRYPTED_V2)
      expect(key.to_payload.bth[0..1]).to eq('02')
      expect(key.salt.htb.bytesize).to eq(Bitcoin::Wallet::MasterKey::SALT_SIZE)
      # [IV][auth tag][ciphertext]
      expect(key.seed.htb.bytesize).to eq(
        Bitcoin::Wallet::MasterKey::GCM_IV_SIZE + Bitcoin::Wallet::MasterKey::GCM_TAG_SIZE + test_seed.bytesize)
    end

    it 'should use a different salt and IV for each encryption' do
      first = Bitcoin::Wallet::MasterKey.new(test_seed)
      first.encrypt('hogehoge')
      second = Bitcoin::Wallet::MasterKey.new(test_seed)
      second.encrypt('hogehoge')
      expect(first.salt).not_to eq(second.salt)
      expect(first.seed).not_to eq(second.seed)
    end

    context 'passphrase is wrong' do
      subject {
        key = Bitcoin::Wallet::MasterKey.new(test_seed)
        key.encrypt('hogehoge')
        key
      }
      it 'should raise error' do
        expect { subject.decrypt('hogehoge1') }.to raise_error(ArgumentError, 'Invalid passphrase.')
      end
    end

    context 'encrypted seed is tampered' do
      subject {
        key = Bitcoin::Wallet::MasterKey.new(test_seed)
        key.encrypt('hogehoge')
        tampered = key.seed.htb
        tampered[-1] = (tampered[-1].ord ^ 0x01).chr
        Bitcoin::Wallet::MasterKey.new(tampered.bth, salt: key.salt, encrypted: true,
                                       encryption_version: Bitcoin::Wallet::MasterKey::ENCRYPTED_V2)
      }
      it 'should raise error' do
        expect { subject.decrypt('hogehoge') }.to raise_error(ArgumentError, 'Invalid passphrase.')
      end
    end

    context 'seed was encrypted with the v1 scheme' do
      # AES-256-CBC with a PBKDF2-HMAC-SHA1 key of 2000 rounds, as written before v2 existed.
      subject {
        Bitcoin::Wallet::MasterKey.parse_from_payload(
          '0110f9d75d45f59a9e07a7b6331a58ceedd7904a7a1f2ef10230ff5afdf2b1cb2c78e1942a40a575cf1e05f57e82d181b9b9e076ab6a702fb6801bb591e563a87f1624960dcf45001aa42142aa3dfb59a2f9b01850ede5bcbd43ad6b242e47053bda306db11f9fd8aabeca69a8eb55a7f81f4f7afa6c33998dc91b8bdb7034c2066a38f1a9a028c2bd395f239c0395c62277338ae1c1d004323f67ad0e46cebb5b1ccd'.htb)
      }
      it 'should still be decrypted' do
        expect(subject.encryption_version).to eq(Bitcoin::Wallet::MasterKey::ENCRYPTED_V1)
        subject.decrypt('hogehoge')
        expect(subject.seed).to eq(test_seed)
      end

      it 'should be upgraded to v2 when encrypted again' do
        subject.decrypt('hogehoge')
        subject.encrypt('hogehoge')
        expect(subject.encryption_version).to eq(Bitcoin::Wallet::MasterKey::ENCRYPTED_V2)
      end
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
