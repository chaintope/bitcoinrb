require 'spec_helper'

RSpec.describe Bitcoin::MessageSign, network: :mainnet do

  describe 'sign_message in Bitcoin Core' do
    it 'should generate signature' do
      message = 'Trust no one'
      private_key = 'd97f5108f11cda6eeebaaa420fef0726b1f898060b98489fa3098463c0032866'
      key = Bitcoin::Key.new(priv_key: private_key, key_type: Bitcoin::Key::TYPES[:compressed])
      expect(key.to_p2pkh).to eq('15CRxFdyRpGZLW9w8HnHvVduizdL5jKNbs')
      expect(Bitcoin::MessageSign.message_hash(message).bth).to eq('aa8215d723ecd2f14867eeb7e19f192be7bc15a2352a24b991d4f5870cbaf6e8')
      signature = Bitcoin::MessageSign.sign_message(key, message)
      expect(signature).to eq('IPojfrX2dfPnH26UegfbGQQLrdK844DlHq5157/P6h57WyuS/Qsl+h/WSVGDF4MUi4rWSswW38oimDYfNNUBUOk=')
      expect(Bitcoin::MessageSign.verify_message(key.to_p2pkh, signature, message)).to be true
    end
  end

  # bitcoinjs-lib fixtures.
  let(:fixtures) { fixture_file('message_signs.json') }

  describe 'Test Vector' do
    context 'valid' do
      let(:valid) { fixtures['valid'] }
      it 'message hash generate hash.' do
        valid['magicHash'].each do |v|
          digest = Bitcoin::MessageSign.message_hash(v['message'], prefix: prefix(v['network']))
          expect(digest.bth).to eq(v['magicHash'])
        end
      end

      it "sign generate signature." do
        valid['sign'].each do |v|
          key = Bitcoin::Key.new(priv_key: ECDSA::Format::IntegerOctetString.encode(v['d'].to_i, 32).bth, compressed: false)
          signature = Bitcoin::MessageSign.sign_message(key, v['message'], prefix: prefix(v['network']))
          expect(signature).to eq(v['signature'])
          if v['compressed']
            key = Bitcoin::Key.new(priv_key: ECDSA::Format::IntegerOctetString.encode(v['d'].to_i, 32).bth)
            signature = Bitcoin::MessageSign.sign_message(key, v['message'], prefix: prefix(v['network']))
            expect(signature).to eq(v['compressed']['signature'])
          end
        end
      end

      it 'verify be true' do
        valid['verify'].select{|v|v['network'] == 'bitcoin'}.each do |v|
          expect(Bitcoin::MessageSign.verify_message(v['address'], v['signature'], v['message'])).to be true
          if v['compressed']
            expect(Bitcoin::MessageSign.verify_message(v['compressed']['address'], v['compressed']['signature'], v['message'])).to be true
          end
        end
      end
    end

    context 'invalid' do
      let(:invalid) { fixtures['invalid'] }

      it 'raise error.' do
        invalid['signature'].each do |v|
          expect{Bitcoin::MessageSign.verify_message('15CRxFdyRpGZLW9w8HnHvVduizdL5jKNbs', Base64.encode64(v['hex'].htb), '')}.
            to raise_error(ArgumentError, v['exception'])
        end
      end

      it 'return false.' do
        invalid['verify'].each do |v|
          expect(Bitcoin::MessageSign.verify_message(v['address'], v['signature'], v['message'])).to be false
        end
      end
    end
  end

  def prefix(network)
    fixtures['networks'][network]
  end

end
