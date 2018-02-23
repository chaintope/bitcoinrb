require 'spec_helper'

# BIP-32 test
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_Vectors
describe Bitcoin::ExtKey, network: :mainnet do

  describe 'Test Vector 1' do

    before do
      @master_key = Bitcoin::ExtKey.generate_master('000102030405060708090a0b0c0d0e0f')
    end

    it 'Chain m' do
      expect(@master_key.depth).to eq(0)
      expect(@master_key.number).to eq(0)
      expect(@master_key.fingerprint).to eq('3442193e')
      expect(@master_key.chain_code.bth).to eq('873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508')
      expect(@master_key.priv).to eq('e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35')
      expect(@master_key.addr).to eq('15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma')
      expect(@master_key.pub).to eq('0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2')
      expect(@master_key.hash160).to eq('3442193e1bb70916e914552172cd4e2dbc9df811')
      expect(@master_key.to_base58).to eq('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi')
      expect(@master_key.ext_pubkey.to_base58).to eq('xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8')
      expect(@master_key.ext_pubkey.pub).to eq('0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2')
      expect(@master_key.ext_pubkey.hash160).to eq('3442193e1bb70916e914552172cd4e2dbc9df811')
      expect(@master_key.ext_pubkey.addr).to eq('15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma')
    end

    it 'Chain m/0H' do
      key = @master_key.derive(2**31)
      expect(key.depth).to eq(1)
      expect(key.hardened?).to be true
      expect(key.fingerprint).to eq('5c1bd648')
      expect(key.chain_code.bth).to eq('47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141')
      expect(key.priv).to eq('edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea')
      expect(key.pub).to eq('035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56')
      expect(key.addr).to eq('19Q2WoS5hSS6T8GjhK8KZLMgmWaq4neXrh')
      expect(key.to_base58).to eq('xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7')
      expect(key.ext_pubkey.to_base58).to eq('xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw')
      expect(key.ext_pubkey.hardened?).to be true
    end

    it 'Chain m/0H/1' do
      key = @master_key.derive(2**31).derive(1)
      expect(key.depth).to eq(2)
      expect(key.hardened?).to be false
      expect(key.fingerprint).to eq('bef5a2f9')
      expect(key.chain_code.bth).to eq('2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19')
      expect(key.priv).to eq('3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368')
      expect(key.to_base58).to eq('xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs')
      expect(key.ext_pubkey.to_base58).to eq('xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ')

      # pubkey derivation
      ext_pubkey = @master_key.derive(2**31).ext_pubkey.derive(1)
      expect(ext_pubkey.to_base58).to eq('xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ')
      expect(key.ext_pubkey.hardened?).to be false
    end

    it 'Chain m/0H/1/2H' do
      key = @master_key.derive(2**31).derive(1).derive(2**31 + 2)
      expect(key.depth).to eq(3)
      expect(key.hardened?).to be true
      expect(key.fingerprint).to eq('ee7ab90c')
      expect(key.chain_code.bth).to eq('04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f')
      expect(key.priv).to eq('cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca')
      expect(key.to_base58).to eq('xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM')
      expect(key.ext_pubkey.to_base58).to eq('xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5')
      expect(key.ext_pubkey.hardened?).to be true
    end

    it 'Chain m/0H/1/2H/2' do
      key = @master_key.derive(2**31).derive(1).derive(2**31 + 2).derive(2)
      expect(key.depth).to eq(4)
      expect(key.hardened?).to be false
      expect(key.fingerprint).to eq('d880d7d8')
      expect(key.chain_code.bth).to eq('cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd')
      expect(key.priv).to eq('0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4')
      expect(key.to_base58).to eq('xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334')
      expect(key.ext_pubkey.to_base58).to eq('xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV')
      expect(key.ext_pubkey.hardened?).to be false
    end

    it 'Chain m/0H/1/2H/2/1000000000' do
      key = @master_key.derive(2**31).derive(1).derive(2**31 + 2).derive(2).derive(1000000000)
      expect(key.depth).to eq(5)
      expect(key.hardened?).to be false
      expect(key.fingerprint).to eq('d69aa102')
      expect(key.chain_code.bth).to eq('c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e')
      expect(key.priv).to eq('471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8')
      expect(key.to_base58).to eq('xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76')
      expect(key.ext_pubkey.to_base58).to eq('xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy')
      expect(key.ext_pubkey.hardened?).to be false
    end
  end

  describe 'Test Vector 2' do
    before do
      @master_key = Bitcoin::ExtKey.generate_master('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542')
    end

    it 'Chain m' do
      expect(@master_key.depth).to eq(0)
      expect(@master_key.number).to eq(0)
      expect(@master_key.to_base58).to eq('xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U')
      expect(@master_key.ext_pubkey.to_base58).to eq('xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB')
    end

    it 'Chain m/0' do
      key = @master_key.derive(0)
      expect(key.depth).to eq(1)
      expect(key.hardened?).to be false
      expect(key.number).to eq(0)
      expect(key.to_base58).to eq('xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt')
      expect(key.ext_pubkey.to_base58).to eq('xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH')
      expect(key.ext_pubkey.hardened?).to be false
    end

    it 'Chain m/0/2147483647H' do
      key = @master_key.derive(0).derive(2**31 + 2147483647)
      expect(key.depth).to eq(2)
      expect(key.hardened?).to be true
      expect(key.number).to eq(2**31 + 2147483647)
      expect(key.to_base58).to eq('xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9')
      expect(key.ext_pubkey.to_base58).to eq('xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a')
      expect(key.ext_pubkey.hardened?).to be true
    end

    it 'Chain m/0/2147483647H/1' do
      key = @master_key.derive(0).derive(2**31 + 2147483647).derive(1)
      expect(key.depth).to eq(3)
      expect(key.hardened?).to be false
      expect(key.number).to eq(1)
      expect(key.to_base58).to eq('xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef')
      expect(key.ext_pubkey.to_base58).to eq('xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon')
      expect(key.ext_pubkey.hardened?).to be false
    end

    it 'Chain m/0/2147483647H/1/2147483646H' do
      key = @master_key.derive(0).derive(2**31 + 2147483647).derive(1).derive(2**31 + 2147483646)
      expect(key.depth).to eq(4)
      expect(key.hardened?).to be true
      expect(key.number).to eq(2**31 + 2147483646)
      expect(key.to_base58).to eq('xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc')
      expect(key.ext_pubkey.to_base58).to eq('xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL')
      expect(key.ext_pubkey.hardened?).to be true
    end

    it 'Chain m/0/2147483647H/1/2147483646H/2' do
      key = @master_key.derive(0).derive(2**31 + 2147483647).derive(1).derive(2**31 + 2147483646).derive(2)
      expect(key.depth).to eq(5)
      expect(key.hardened?).to be false
      expect(key.number).to eq(2)
      expect(key.to_base58).to eq('xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j')
      expect(key.ext_pubkey.to_base58).to eq('xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt')
      ext_pubkey = @master_key.derive(0).derive(2**31 + 2147483647).derive(1).derive(2**31 + 2147483646).ext_pubkey.derive(2)
      expect(ext_pubkey.to_base58).to eq('xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt')
      expect(key.ext_pubkey.hardened?).to be false
    end

  end

  describe 'import from base58 address' do

    it 'import private key' do
      # normal key
      key = Bitcoin::ExtKey.from_base58('xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs')
      expect(key.depth).to eq(2)
      expect(key.number).to eq(1)
      expect(key.chain_code.bth).to eq('2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19')
      expect(key.priv).to eq('3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368')
      expect(key.ext_pubkey.to_base58).to eq('xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ')

      # hardended key
      key = Bitcoin::ExtKey.from_base58('xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM')
      expect(key.depth).to eq(3)
      expect(key.number).to eq(2**31 + 2)
      expect(key.fingerprint).to eq('ee7ab90c')
      expect(key.chain_code.bth).to eq('04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f')
      expect(key.priv).to eq('cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca')
      expect(key.to_base58).to eq('xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM')
      expect(key.ext_pubkey.to_base58).to eq('xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5')

      # pubkey format
      expect{Bitcoin::ExtKey.from_base58('xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ')}.to raise_error('An unsupported version byte was specified.')
    end

    it 'import public key' do
      # normal key
      key = Bitcoin::ExtPubkey.from_base58('xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ')
      expect(key.depth).to eq(2)
      expect(key.number).to eq(1)
      expect(key.chain_code.bth).to eq('2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19')
      expect(key.to_base58).to eq('xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ')
      expect(key.pubkey).to eq('03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c')

      # hardended key
      key = Bitcoin::ExtPubkey.from_base58('xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5')
      expect(key.depth).to eq(3)
      expect(key.number).to eq(2**31 + 2)
      expect(key.fingerprint).to eq('ee7ab90c')
      expect(key.chain_code.bth).to eq('04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f')
      expect(key.pubkey).to eq('0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2')

      # priv key format
      expect{Bitcoin::ExtPubkey.from_base58('xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM')}.to raise_error('An unsupported version byte was specified.')
    end
  end

  describe 'pubkey hardended derive' do
    it 'should raise error' do
      key = Bitcoin::ExtPubkey.from_base58('xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5')
      expect{key.derive(2**31)}.to raise_error('hardened key is not support')
    end
  end

  describe '#parse_from_payload' do
    it 'should deserialize key object.' do
      ext_pubkey = Bitcoin::ExtPubkey.parse_from_payload('0488b21e03bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2'.htb)
      expect(ext_pubkey.to_base58).to eq('xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5')

      key = Bitcoin::ExtKey.parse_from_payload('0488ade4025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19003c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368'.htb)
      expect(key.to_base58).to eq('xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs')
    end
  end

  # https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki#Test_vectors
  describe 'bip 49' do
    before do
      # m/49'/1'/0'
      @account = test_master_key.key.derive(2**31 + 49).derive(2**31 + 1).derive(2**31)
    end

    context 'testnet', network: :testnet do
      it 'should be used bip44 encoding' do
        # m/49'/1'/0'/0/0
        receive_key = @account.derive(0).derive(0)
        expect(receive_key.version).to eq('044a4e28')
        expect(receive_key.priv).to eq('c9bdb49cfbaedca21c4b1f3a7803c34636b1d7dc55a717132443fc3f4c5867e8')
        expect(receive_key.pub).to eq('03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f')
        expect(receive_key.ext_pubkey.pub).to eq('03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f')
        expect(receive_key.ext_pubkey.version).to eq('044a5262')
        # address derivation for P2WPKH-in-P2SH
        expect(receive_key.addr).to eq('2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2')
      end
    end
  end

  # https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki#Test_vectors
  describe 'bip 84' do
    before do
      # m/84'/0'/0'
      @account = test_master_key.key.derive(2**31 + 84).derive(2**31).derive(2**31)
    end
    it 'should be changed version bytes' do
      expect(@account.to_base58).to eq('zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE')
      expect(@account.ext_pubkey.to_base58).to eq('zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs')

      # m/84'/0'/0'/0/0
      receive_key = @account.derive(0).derive(0)
      expect(receive_key.pub).to eq('0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c')
      expect(receive_key.addr).to eq('bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu')

      # m/84'/0'/0'/0/1
      receive_key2 = @account.derive(0).derive(1)
      expect(receive_key2.pub).to eq('03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77')
      expect(receive_key2.addr).to eq('bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g')

      # m/84'/0'/0'/1/0
      change_key = @account.derive(1).derive(0)
      expect(change_key.pub).to eq('03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6')
      expect(change_key.addr).to eq('bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el')

      # recover from xprv
      ext_prv = Bitcoin::ExtKey.from_base58('zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE')
      expect(ext_prv.version).to eq('04b2430c')
      expect(ext_prv.derive(0).derive(0).addr).to eq('bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu')

      # recover from xpub
      ext_pub = Bitcoin::ExtPubkey.from_base58('zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs')
      expect(ext_pub.version).to eq('04b24746')
      expect(ext_pub.derive(0).derive(0).addr).to eq('bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu')
    end
  end

end
