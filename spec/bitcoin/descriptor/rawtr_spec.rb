require 'spec_helper'

RSpec.describe Bitcoin::Descriptor::RawTr, network: :mainnet do
  include Bitcoin::Descriptor

  describe 'rawtr()' do
    it do
      expect(rawtr("xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/86'/1'/0'/1/0").to_hex).
        to eq('51205172af752f057d543ce8e4a6f8dcf15548ec6be44041bfa93b72e191cfc8c1ee')
      desc_rawtr = "rawtr(xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/86'/1'/0'/1/0)#q8dqvgc8"
      rawtr = Bitcoin::Descriptor.parse(desc_rawtr)
      expect(rawtr.to_s(checksum: true)).to eq(desc_rawtr)
      expect(rawtr('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1').to_hex).to eq('5120a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd')
      desc_rawtr = "rawtr(xpub68FQ9imX6mCWacw6eNRjaa8q8ynnHmUd5i7MVR51ZMPP5JycyfVHSLQVFPHMYiTybWJnSBL2tCBpy6aJTR2DYrshWYfwAxs8SosGXd66d8/*, xpub69Mvq3QMipdvnd9hAyeTnT5jrkcBuLErV212nsGf3qr7JPWysc9HnNhCsazdzj1etSx28hPSE8D7DnceFbNdw4Kg8SyRfjE2HFLv1P8TSGc/*)"
      expect{Bitcoin::Descriptor.parse(desc_rawtr)}.to raise_error(ArgumentError)
    end
  end

end