require 'spec_helper'

describe Bitcoin::Descriptor::Sp do
  include Bitcoin::Descriptor

  # Test keys from BIP-392 examples
  let(:wif_scan_key) { 'L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1' }
  let(:spend_pubkey) { '0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600' }

  describe 'mainnet', network: :mainnet do
    describe 'basic sp() with WIF and pubkey' do
      subject { sp(wif_scan_key, spend_pubkey) }

      it 'creates descriptor' do
        expect(subject.type).to eq(:sp)
        expect(subject.top_level?).to be true
        expect(subject.args).to eq("#{wif_scan_key},#{spend_pubkey}")
      end

      it 'generates silent payment address' do
        address = subject.to_addr
        expect(address).to be_a(Bech32::SilentPaymentAddr)
        expect(address.to_s).to start_with('sp1qq')
      end

      it 'raises error for to_script' do
        expect { subject.to_script }.to raise_error(RuntimeError, /does not produce a fixed script/)
      end

      it 'generates descriptor string' do
        expect(subject.to_s).to eq("sp(#{wif_scan_key},#{spend_pubkey})")
      end
    end

    describe 'sp() with xprv' do
      let(:xprv) { 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi' }
      let(:xpub) { 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8' }

      subject { sp(xprv, xpub) }

      it 'creates descriptor with extended keys' do
        expect(subject.type).to eq(:sp)
        address = subject.to_addr
        expect(address.to_s).to start_with('sp1qq')
      end
    end

    describe 'sp() with derivation path' do
      let(:xprv) { 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi' }
      let(:xpub) { 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8' }

      subject { sp("#{xprv}/0'", "#{xpub}/0") }

      it 'creates descriptor with derivation paths' do
        expect(subject.type).to eq(:sp)
        address = subject.to_addr
        expect(address.to_s).to start_with('sp1qq')
      end

      it 'generates correct descriptor string' do
        expect(subject.to_s).to eq("sp(#{xprv}/0',#{xpub}/0)")
      end
    end

    describe 'sp() with key origin' do
      subject { sp("[deadbeef/352'/0'/0']#{wif_scan_key}", spend_pubkey) }

      it 'creates descriptor with key origin' do
        expect(subject.type).to eq(:sp)
        address = subject.to_addr
        expect(address.to_s).to start_with('sp1qq')
      end

      it 'generates correct descriptor string' do
        expect(subject.to_s).to eq("sp([deadbeef/352'/0'/0']#{wif_scan_key},#{spend_pubkey})")
      end
    end

    describe 'sp() with MuSig spend key' do
      let(:pubkey1) { '03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0' }
      let(:pubkey2) { '0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600' }
      let(:musig_key) { musig(pubkey1, pubkey2) }

      subject { sp(wif_scan_key, musig_key) }

      it 'creates descriptor with MuSig' do
        expect(subject.type).to eq(:sp)
        address = subject.to_addr
        expect(address.to_s).to start_with('sp1qq')
      end

      it 'generates correct descriptor string' do
        expect(subject.to_s).to eq("sp(#{wif_scan_key},musig(#{pubkey1},#{pubkey2}))")
      end
    end

    describe 'sp() with spscan (single-argument form)' do
      # Generate spscan encoded key: scan_priv (32 bytes) + spend_pub (33 bytes)
      let(:scan_key) { Bitcoin::Key.from_wif(wif_scan_key) }
      let(:spend_key) { Bitcoin::Key.new(pubkey: spend_pubkey) }
      let(:spscan_payload) { scan_key.priv_key.htb + spend_key.pubkey.htb }
      let(:spscan_data) { [0] + Bech32.convert_bits(spscan_payload.unpack('C*'), 8, 5) }
      let(:spscan_key) { Bech32.encode('spscan', spscan_data, Bech32::Encoding::BECH32M) }

      subject { sp(spscan_key) }

      it 'creates descriptor from spscan key' do
        expect(subject.type).to eq(:sp)
        expect(subject.single_key?).to be true
        expect(subject.has_spend_private_key?).to be false
      end

      it 'generates correct silent payment address' do
        # Should generate same address as two-argument form
        two_arg = sp(wif_scan_key, spend_pubkey)
        expect(subject.to_addr.to_s).to eq(two_arg.to_addr.to_s)
      end

      it 'generates descriptor string with spscan key' do
        expect(subject.to_s).to eq("sp(#{spscan_key})")
      end

      it 'parses spscan descriptor' do
        desc_str = "sp(#{spscan_key})"
        parsed = Bitcoin::Descriptor.parse(desc_str)
        expect(parsed.type).to eq(:sp)
        expect(parsed.single_key?).to be true
        expect(parsed.to_s).to eq(desc_str)
      end
    end

    describe 'sp() with spspend (single-argument form)' do
      # Generate spspend encoded key: scan_priv (32 bytes) + spend_priv (32 bytes)
      let(:scan_key) { Bitcoin::Key.from_wif(wif_scan_key) }
      let(:spend_key) { Bitcoin::Key.generate }
      let(:spspend_payload) { scan_key.priv_key.htb + spend_key.priv_key.htb }
      let(:spspend_data) { [0] + Bech32.convert_bits(spspend_payload.unpack('C*'), 8, 5) }
      let(:spspend_key) { Bech32.encode('spspend', spspend_data, Bech32::Encoding::BECH32M) }

      subject { sp(spspend_key) }

      it 'creates descriptor from spspend key' do
        expect(subject.type).to eq(:sp)
        expect(subject.single_key?).to be true
        expect(subject.has_spend_private_key?).to be true
      end

      it 'generates silent payment address' do
        address = subject.to_addr
        expect(address.to_s).to start_with('sp1qq')
      end

      it 'generates descriptor string with spspend key' do
        expect(subject.to_s).to eq("sp(#{spspend_key})")
      end
    end

    describe 'sp() with key origin and spscan' do
      let(:scan_key) { Bitcoin::Key.from_wif(wif_scan_key) }
      let(:spend_key) { Bitcoin::Key.new(pubkey: spend_pubkey) }
      let(:spscan_payload) { scan_key.priv_key.htb + spend_key.pubkey.htb }
      let(:spscan_data) { [0] + Bech32.convert_bits(spscan_payload.unpack('C*'), 8, 5) }
      let(:spscan_key) { Bech32.encode('spscan', spscan_data, Bech32::Encoding::BECH32M) }

      subject { sp("[deadbeef/352'/0'/0']#{spscan_key}") }

      it 'creates descriptor with key origin' do
        expect(subject.type).to eq(:sp)
        expect(subject.single_key?).to be true
        address = subject.to_addr
        expect(address.to_s).to start_with('sp1qq')
      end
    end

    describe 'parsing' do
      it 'parses basic sp() descriptor' do
        desc_str = "sp(#{wif_scan_key},#{spend_pubkey})"
        parsed = Bitcoin::Descriptor.parse(desc_str)
        expect(parsed.type).to eq(:sp)
        expect(parsed.to_s).to eq(desc_str)
      end

      it 'parses sp() with MuSig' do
        pubkey1 = '03669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0'
        pubkey2 = '0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600'
        desc_str = "sp(#{wif_scan_key},musig(#{pubkey1},#{pubkey2}))"
        parsed = Bitcoin::Descriptor.parse(desc_str)
        expect(parsed.type).to eq(:sp)
        expect(parsed.to_s).to eq(desc_str)
        expect(parsed.to_addr.to_s).to start_with('sp1qq')
      end

      it 'parsed descriptor generates same address' do
        original = sp(wif_scan_key, spend_pubkey)
        parsed = Bitcoin::Descriptor.parse(original.to_s)
        expect(parsed.to_addr.to_s).to eq(original.to_addr.to_s)
      end
    end

    describe 'invalid cases' do
      it 'raises error when scan key is public key' do
        expect { sp(spend_pubkey, spend_pubkey) }.to raise_error(ArgumentError, /Scan key must be a private key/)
      end

      it 'raises error when scan key is xpub' do
        xpub = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
        expect { sp(xpub, spend_pubkey) }.to raise_error(ArgumentError, /Scan key must be a private key/)
      end

      it 'raises error for uncompressed spend key' do
        uncompressed = '04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235'
        expect { sp(wif_scan_key, uncompressed) }.to raise_error(ArgumentError, /Uncompressed keys are not allowed/)
      end

      it 'raises error when parsing sp() with invalid single argument (not spscan/spspend)' do
        # WIF is not a valid spscan/spspend encoding
        expect { Bitcoin::Descriptor.parse("sp(#{wif_scan_key})") }.to raise_error(ArgumentError, /Invalid spscan\/spspend encoding/)
      end
    end

    describe 'checksum' do
      it 'generates and validates checksum' do
        desc = sp(wif_scan_key, spend_pubkey)
        desc_with_checksum = desc.to_s(checksum: true)
        expect(desc_with_checksum).to match(/#[a-z0-9]{8}$/)

        # Parse with checksum should work
        parsed = Bitcoin::Descriptor.parse(desc_with_checksum)
        expect(parsed.to_addr.to_s).to eq(desc.to_addr.to_s)
      end
    end
  end

  describe 'testnet', network: :testnet do
    it 'generates tsp address' do
      # Use testnet WIF format (starts with 'c')
      testnet_key = Bitcoin::Key.generate
      testnet_wif = testnet_key.to_wif
      desc = sp(testnet_wif, spend_pubkey)
      address = desc.to_addr
      expect(address.to_s).to start_with('tsp1qq')
    end

    describe 'tspscan (single-argument form)' do
      let(:scan_key) { Bitcoin::Key.generate }
      let(:spend_key) { Bitcoin::Key.new(pubkey: spend_pubkey) }
      let(:tspscan_payload) { scan_key.priv_key.htb + spend_key.pubkey.htb }
      let(:tspscan_data) { [0] + Bech32.convert_bits(tspscan_payload.unpack('C*'), 8, 5) }
      let(:tspscan_key) { Bech32.encode('tspscan', tspscan_data, Bech32::Encoding::BECH32M) }

      subject { sp(tspscan_key) }

      it 'creates descriptor from tspscan key' do
        expect(subject.type).to eq(:sp)
        expect(subject.single_key?).to be true
        expect(subject.has_spend_private_key?).to be false
      end

      it 'generates tsp address' do
        expect(subject.to_addr.to_s).to start_with('tsp1qq')
      end
    end

    describe 'tspspend (single-argument form)' do
      let(:scan_key) { Bitcoin::Key.generate }
      let(:spend_key) { Bitcoin::Key.generate }
      let(:tspspend_payload) { scan_key.priv_key.htb + spend_key.priv_key.htb }
      let(:tspspend_data) { [0] + Bech32.convert_bits(tspspend_payload.unpack('C*'), 8, 5) }
      let(:tspspend_key) { Bech32.encode('tspspend', tspspend_data, Bech32::Encoding::BECH32M) }

      subject { sp(tspspend_key) }

      it 'creates descriptor from tspspend key' do
        expect(subject.type).to eq(:sp)
        expect(subject.single_key?).to be true
        expect(subject.has_spend_private_key?).to be true
      end

      it 'generates tsp address' do
        expect(subject.to_addr.to_s).to start_with('tsp1qq')
      end
    end
  end

  describe 'signet', network: :signet do
    it 'generates tsp address' do
      # Use signet WIF format (same as testnet, starts with 'c')
      signet_key = Bitcoin::Key.generate
      signet_wif = signet_key.to_wif
      desc = sp(signet_wif, spend_pubkey)
      address = desc.to_addr
      expect(address.to_s).to start_with('tsp1qq')
    end
  end
end
