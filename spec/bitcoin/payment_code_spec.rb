require 'spec_helper'

# BIP-47 test
# https://gist.github.com/SamouraiDev/6aad669604c5930864bd
describe Bitcoin::PaymentCode, network: :mainnet do

  describe "Alice's Wallet" do
    before do
      @payment_code = Bitcoin::PaymentCode.generate_master('64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a')
    end

    it 'generates Payment Code for Alice' do
      expect(@payment_code.to_base58).to eq('PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA')
    end
  end

  describe "Bob's Wallet" do
    before do
      @payment_code = Bitcoin::PaymentCode.generate_master('87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110')
    end

    it 'generates Payment Code for Bob' do
      expect(@payment_code.to_base58).to eq('PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97')
    end

    it 'derive ECDH parameters' do
      expect(@payment_code.derive(0).priv).to eq('04448fd1be0c9c13a5ca0b530e464b619dc091b299b98c5cab9978b32b4a1b8b')
      expect(@payment_code.derive(0).pub).to eq('024ce8e3b04ea205ff49f529950616c3db615b1e37753858cc60c1ce64d17e2ad8')
      expect(@payment_code.derive(1).priv).to eq('6bfa917e4c44349bfdf46346d389bf73a18cec6bc544ce9f337e14721f06107b')
      expect(@payment_code.derive(1).pub).to eq('03e092e58581cf950ff9c8fc64395471733e13f97dedac0044ebd7d60ccc1eea4d')
      expect(@payment_code.derive(2).priv).to eq('46d32fbee043d8ee176fe85a18da92557ee00b189b533fce2340e4745c4b7b8c')
      expect(@payment_code.derive(2).pub).to eq('029b5f290ef2f98a0462ec691f5cc3ae939325f7577fcaf06cfc3b8fc249402156')
      expect(@payment_code.derive(3).priv).to eq('4d3037cfd9479a082d3d56605c71cbf8f38dc088ba9f7a353951317c35e6c343')
      expect(@payment_code.derive(3).pub).to eq('02094be7e0eef614056dd7c8958ffa7c6628c1dab6706f2f9f45b5cbd14811de44')
      expect(@payment_code.derive(4).priv).to eq('97b94a9d173044b23b32f5ab64d905264622ecd3eafbe74ef986b45ff273bbba')
      expect(@payment_code.derive(4).pub).to eq('031054b95b9bc5d2a62a79a58ecfe3af000595963ddc419c26dab75ee62e613842')
      expect(@payment_code.derive(5).priv).to eq('ce67e97abf4772d88385e66d9bf530ee66e07172d40219c62ee721ff1a0dca01')
      expect(@payment_code.derive(5).pub).to eq('03dac6d8f74cacc7630106a1cfd68026c095d3d572f3ea088d9a078958f8593572')
      expect(@payment_code.derive(6).priv).to eq('ef049794ed2eef833d5466b3be6fe7676512aa302afcde0f88d6fcfe8c32cc09')
      expect(@payment_code.derive(6).pub).to eq('02396351f38e5e46d9a270ad8ee221f250eb35a575e98805e94d11f45d763c4651')
      expect(@payment_code.derive(7).priv).to eq('d3ea8f780bed7ef2cd0e38c5d943639663236247c0a77c2c16d374e5a202455b')
      expect(@payment_code.derive(7).pub).to eq('039d46e873827767565141574aecde8fb3b0b4250db9668c73ac742f8b72bca0d0')
      expect(@payment_code.derive(8).priv).to eq('efb86ca2a3bad69558c2f7c2a1e2d7008bf7511acad5c2cbf909b851eb77e8f3')
      expect(@payment_code.derive(8).pub).to eq('038921acc0665fd4717eb87f81404b96f8cba66761c847ebea086703a6ae7b05bd')
      expect(@payment_code.derive(9).priv).to eq('18bcf19b0b4148e59e2bba63414d7a8ead135a7c2f500ae7811125fb6f7ce941')
      expect(@payment_code.derive(9).pub).to eq('03d51a06c6b48f067ff144d5acdfbe046efa2e83515012cf4990a89341c1440289')
    end
  end

  describe "Alice's notification transaction to Bob" do
    before do
      @alice_payment_code = Bitcoin::PaymentCode.generate_master('64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a')
      @bob_payment_code = Bitcoin::PaymentCode.generate_master('87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110')
    end

    it 'generates notification address' do
      expect(@alice_payment_code.notification_address).to eq('1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW')
      expect(@bob_payment_code.notification_address).to eq('1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV')
      expect(@bob_payment_code.derive(0).pub).to eq('024ce8e3b04ea205ff49f529950616c3db615b1e37753858cc60c1ce64d17e2ad8')
    end
  end

  describe 'Decode Payment Code' do
    it 'decodes Base58 encoded payment code' do
      expect(Bitcoin::PaymentCode.from_base58('PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA').bth).to eq('010002b85034fb08a8bfefd22848238257b252721454bbbfba2c3667f168837ea2cdad671af9f65904632e2dcc0c6ad314e11d53fc82fa4c4ea27a4a14eccecc478fee00000000000000000000000000')
      expect{Bitcoin::PaymentCode.from_base58('PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GB').bth}.to raise_error(ArgumentError, 'invalid checksum')
    end
  end
end
