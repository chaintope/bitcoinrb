require 'spec_helper'

describe Bitcoin::Store::ChainEntry do

  describe '#to_payload' do
    it 'should be parsed' do
      header = Bitcoin::BlockHeader.parse_from_payload('0000002021db4eba7c84958483205b6cdda9192bc42069c2a78143497283253200000000c420e732f0c35c2e2375ef41c247cece722dc87382d1a5f0f18854e9973b4846518bdc59ffff001dea3dba3d'.htb)
      entry1 = Bitcoin::Store::ChainEntry.new(header, 1209901)
      expect(entry1.to_payload.bth).to eq('032d76120000002021db4eba7c84958483205b6cdda9192bc42069c2a78143497283253200000000c420e732f0c35c2e2375ef41c247cece722dc87382d1a5f0f18854e9973b4846518bdc59ffff001dea3dba3d')

      header2 = Bitcoin::BlockHeader.parse_from_payload('0100000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000bac8b0fa927c0ac8234287e33c5f74d38d354820e24756ad709d7038fc5f31f020e7494dffff001d03e4b672'.htb)
      entry2 = Bitcoin::Store::ChainEntry.new(header2, 1)
      expect(entry2.to_payload.bth).to eq('01010100000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000bac8b0fa927c0ac8234287e33c5f74d38d354820e24756ad709d7038fc5f31f020e7494dffff001d03e4b672')
    end
  end

  describe '#parse_from_payload' do
    it 'should be parsed' do
      entry1 = Bitcoin::Store::ChainEntry.parse_from_payload('032d76120000002021db4eba7c84958483205b6cdda9192bc42069c2a78143497283253200000000c420e732f0c35c2e2375ef41c247cece722dc87382d1a5f0f18854e9973b4846518bdc59ffff001dea3dba3d'.htb)
      expect(entry1.height).to eq(1209901)
      expect(entry1.header.to_payload.bth).to eq('0000002021db4eba7c84958483205b6cdda9192bc42069c2a78143497283253200000000c420e732f0c35c2e2375ef41c247cece722dc87382d1a5f0f18854e9973b4846518bdc59ffff001dea3dba3d')

      entry2 = Bitcoin::Store::ChainEntry.parse_from_payload('01010100000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000bac8b0fa927c0ac8234287e33c5f74d38d354820e24756ad709d7038fc5f31f020e7494dffff001d03e4b672'.htb)
      expect(entry2.height).to eq(1)
      expect(entry2.header.to_payload.bth).to eq('0100000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000bac8b0fa927c0ac8234287e33c5f74d38d354820e24756ad709d7038fc5f31f020e7494dffff001d03e4b672')
    end
  end

end