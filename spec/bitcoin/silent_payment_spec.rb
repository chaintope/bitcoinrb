require 'spec_helper'

RSpec.describe Bitcoin::SilentPayment, network: :mainnet, use_secp256k1: true do

  # Build the tx, the prevout scripts and the input keys a test vector's vin describes.
  # @param [Array] vin The vin of a test vector.
  # @return [Array] tx, prevout scripts and the private key of each input.
  def parse_vin(vin)
    tx = Bitcoin::Tx.new
    prevouts = []
    private_keys = []
    vin.each do |i|
      tx.in << Bitcoin::TxIn.new(out_point: Bitcoin::OutPoint.from_txid(i['txid'], i['vout']),
                                 script_sig: Bitcoin::Script.parse_from_payload(i['scriptSig'].htb),
                                 script_witness: Bitcoin::ScriptWitness.parse_from_payload(i['txinwitness'].htb))
      prevouts << Bitcoin::Script.parse_from_payload(i['prevout']['scriptPubKey']['hex'].htb)
      # Only a sending vector gives the key of its inputs.
      private_keys << Bitcoin::Key.new(priv_key: i['private_key']) if i['private_key']
    end
    [tx, prevouts, private_keys]
  end

  describe 'BIP352 Test Vector' do
    fixture_file('bip352/send_and_receive_test_vectors.json').each do |vector|
      # The only vector where sending is expected to fail and the recipient stops scanning
      # once it reaches the limit rather than reporting the outputs it found.
      k_max = vector['comment'].include?('K_max')

      context vector['comment'] do
        it 'should derive the outputs of a sender' do
          vector['sending'].each do |sending|
            given = sending['given']
            tx, prevouts, private_keys = parse_vin(given['vin'])
            recipients = given['recipients'].flat_map do |r|
              Array.new(r['count'] || 1) { Bech32::SilentPaymentAddr.parse(r['address']) }
            end
            if k_max
              expect { tx.derive_payment_points(prevouts, private_keys, recipients) }.
                to raise_error(ArgumentError, /K_max/)
            else
              outputs = tx.derive_payment_points(prevouts, private_keys, recipients)
              expect(outputs.map{|o|o.x.to_s(16)}).to have_same_elements_as_any_of(sending['expected']['outputs'])
            end
          end
        end

        it 'should scan the outputs of a recipient' do
          vector['receiving'].each do |receiving|
            given = receiving['given']
            tx, prevouts, = parse_vin(given['vin'])
            # Script.to_p2tr takes the x-only key as it is. Building the output through
            # Key.from_xonly_pubkey instead would reject the all zero key of the point at
            # infinity vector, which is a scriptPubkey a tx can carry, and leave that vector
            # with an empty tx to scan.
            given['outputs'].each do |o|
              tx.out << Bitcoin::TxOut.new(script_pubkey: Bitcoin::Script.to_p2tr(o))
            end
            expect(tx.out.size).to eq(given['outputs'].size)
            scan_priv_key = Bitcoin::Key.new(priv_key: given['key_material']['scan_priv_key'])
            spend_pubkey = Bitcoin::Key.new(priv_key: given['key_material']['spend_priv_key'])
            outputs = tx.scan_sp_outputs(prevouts, scan_priv_key, spend_pubkey, given['labels'] || [])

            expected = receiving['expected']
            if expected['n_outputs'] # K_max
              expect(outputs.length).to eq(expected['n_outputs'])
            else
              expect(outputs.map(&:pubkey)).to match_array(expected['outputs'].map{|o|o['pub_key']})
              expect(outputs.map(&:tweak_hex)).to match_array(expected['outputs'].map{|o|o['priv_key_tweak']})
            end
          end
        end
      end
    end
  end
end
