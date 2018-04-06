require 'spec_helper'

describe Bitcoin::Payments do

  let(:payment_tx) {
    Bitcoin::Tx.parse_from_payload('01000000000101813a3ac6758c0f2e694511d200dd7579a9bd41d3a0944db0830c2215a6e8787a01000000171600141f2ea9cfd793adbec07e65d5753a196fe6531833ffffffff0320a10700000000001976a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac10270000000000001976a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac40b9ec05000000001976a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac02473044022073a534f937c61ebdcc5ccf9260e2fe6584791aa9a6ba81f606742fd9ce7c5773022017ce7308b0243ce6dad71d213e5198616f720b369131bf39ddd29d1c3c553fa4012103ffb0f2ff41f3483d82aec728b0c1cf08c027ec6868346504f8589fafba3004d200000000'.htb)
  }

  let(:refund_to) {
    refund_script = Bitcoin::Script.to_p2pkh(Bitcoin.hash160('0292ee82d9add0512294723f2c363aee24efdeb3f258cdaf5118a4fcf5263e92c9'))
    refund_out = Bitcoin::TxOut.new(value: 99400000, script_pubkey: refund_script)
    Bitcoin::Payments::Output.new(script: refund_out.to_payload, amount: 510000)
  }

  describe 'PaymentRequest#parse_from_payload' do
    after {
      Timecop.return
    }
    subject {
      Bitcoin::Payments::PaymentRequest.parse_from_payload(load_payment('r1521439154.bitcoinpaymentrequest'))
    }
    it 'should be parsed.' do
      expect(subject.payment_details_version).to eq(1)
      expect(subject.pki_type).to eq('x509+sha1')
      details = subject.details
      expect(details.network).to eq('test')
      expect(details.outputs.size).to eq(2)
      expect(details.outputs[0].to_tx_out.value).to eq(500000)
      expect(details.outputs[0].to_tx_out.script_pubkey.addresses.first).to eq('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F1')
      expect(details.outputs[1].to_tx_out.value).to eq(10000)
      expect(details.outputs[1].to_tx_out.script_pubkey.addresses.first).to eq('mmy7BEH1SUGAeSVUR22pt5hPaejo2645F1')
      expect(details.time).to eq(1521435554)
      expect(details.expires).to eq(1521442754)
      expect(details.memo).to eq('びっとこいん')
      expect(details.payment_url).to eq('http://localhost:8000/payACK.php')
      expect(details.merchant_data.bth).to eq('11d46fe2d93fba568e4443abeb6a20b235616166353162323734643739')
      certs = subject.certs
      expect(certs.size).to eq(1)
      expect(subject.valid_sig?).to be true
      expect(subject.valid_time?).to be false
      Timecop.freeze(Time.utc(2017, 3, 18, 15, 13, 25))
      expect(subject.valid_time?).to be true
    end
  end

  describe 'Payment#parse_from_payload' do
    subject {
      Bitcoin::Payments::Payment.parse_from_payload(load_payment('r1521439154.bitcoinpayment'))
    }
    it 'should be parsed.' do
      expect(subject.merchant_data.bth).to eq('11d46fe2d93fba568e4443abeb6a20b235616166353162323734643739')
      expect(subject.transactions).to eq([payment_tx])
      expect(subject.refund_to).to eq([refund_to])
      expect(subject.memo).to eq('ぺいめんと')
    end
  end

  describe 'PaymentACK#parse_from_payload' do
    subject {
      Bitcoin::Payments::PaymentACK.parse_from_payload(load_payment('r1521439154.bitcoinpaymentack'))
    }
    it 'should be parsed.' do
      expect(subject.payment).to eq(Bitcoin::Payments::Payment.decode(load_payment('r1521439154.bitcoinpayment')))
      expect(subject.memo).to eq('ACK message')
    end
  end

end