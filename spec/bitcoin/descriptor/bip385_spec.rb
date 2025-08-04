require 'spec_helper'

RSpec.describe Bitcoin::Descriptor::Tr, network: :mainnet do

  include Bitcoin::Descriptor

  describe "BIP-385" do
    it do
      desc_raw = 'raw(deadbeef)'
      raw = Bitcoin::Descriptor.parse(desc_raw)
      expect(raw.to_hex).to eq("deadbeef")
      expect(raw("deadbeef")).to eq(raw)
      expect(raw.to_s(checksum: true)).to eq("#{desc_raw}#89f8spxm")

      expect{raw('asdf')}.to raise_error(ArgumentError, "Raw script is not hex.")
      expect{sh(raw('deadbeef'))}.to raise_error(ArgumentError, "Can only have raw() at top level.")
      expect{wsh(raw('deadbeef'))}.to raise_error(ArgumentError, "Can only have raw() at top level.")

      p2sh = "3PUNyaW7M55oKWJ3kDukwk9bsKvryra15j"
      desc_addr = "addr(#{p2sh})"
      addr = Bitcoin::Descriptor.parse(desc_addr)
      expect(addr.to_hex).to eq("a914eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee87")
      expect(addr('3PUNyaW7M55oKWJ3kDukwk9bsKvryra15j')).to eq(addr)
      expect(addr.to_s(checksum: true)).to eq("#{desc_addr}#6vhk2xgr")

      expect{addr('asdf')}.to raise_error(ArgumentError, "Address is not valid.")
      expect{sh(addr(p2sh))}.to raise_error(ArgumentError, "Can only have addr() at top level.")
      expect{wsh(addr(p2sh))}.to raise_error(ArgumentError, "Can only have addr() at top level.")
    end
  end
end