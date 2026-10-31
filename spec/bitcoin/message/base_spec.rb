require 'spec_helper'

RSpec.describe Bitcoin::Message::Base do

  describe '#from_pkt' do
    context 'message is shorter than a header' do
      it 'should raise error' do
        expect { Bitcoin::Message::Base.from_pkt(Bitcoin.chain_params.magic_head.htb + 'ping'.b) }.
          to raise_error(ArgumentError, 'Message header is too short.')
      end
    end

    context 'command has a byte after its NUL padding' do
      it 'should raise error' do
        payload = ''.b
        header = Bitcoin.chain_params.magic_head.htb + "verack\x00\x00x\x00\x00\x00".b + [0].pack('V') + Bitcoin.double_sha256(payload)[0...4]
        expect { Bitcoin::Message::Base.from_pkt(header) }.to raise_error(ArgumentError, 'Invalid command.')
      end
    end

    subject {
      Bitcoin::Message::Base.from_pkt('0b11090776657273696f6e000000000067000000613c82ee7f1101000000000000000000cf31455900000000080000000000000000000000000000000000ffff7f000001479d080000000000000000000000000000000000ffff7f000001479d40abec703bf6eeba112f626974636f696e72623a302e312e302f0000000000'.htb)
    }
    it 'should get version object.' do
      expect(subject).to be_a(Bitcoin::Message::Version)
      expect(subject.to_pkt.bth).to eq('0b11090776657273696f6e000000000067000000613c82ee7f1101000000000000000000cf31455900000000080000000000000000000000000000000000ffff7f000001479d080000000000000000000000000000000000ffff7f000001479d40abec703bf6eeba112f626974636f696e72623a302e312e302f0000000000')
    end

    # [magic][command(12)][payload length(4)][checksum(4)][payload]
    def build_pkt(length, payload = '')
      Bitcoin.chain_params.magic_head.htb << 'verack'.ljust(12, "\x00") <<
        [length].pack('V') << Bitcoin.double_sha256(payload)[0...4] << payload
    end

    context 'announced length exceeds the maximum' do
      # The length comes from the peer, so it is checked before it is used to read.
      subject {
        Bitcoin::Message::Base.from_pkt(build_pkt(Bitcoin::Message::MAX_PROTOCOL_MESSAGE_LENGTH + 1))
      }
      it 'should raise error' do
        expect { subject }.to raise_error(
          ArgumentError,
          "Payload must not be longer than #{Bitcoin::Message::MAX_PROTOCOL_MESSAGE_LENGTH} bytes.")
      end
    end

    context 'payload is shorter than the announced length' do
      subject { Bitcoin::Message::Base.from_pkt(build_pkt(100)) }
      it 'should raise error' do
        expect { subject }.to raise_error(ArgumentError, 'Payload is shorter than the announced length.')
      end
    end

    context 'payload is empty' do
      subject { Bitcoin::Message::Base.from_pkt(build_pkt(0)) }
      it 'should get verack object.' do
        expect(subject).to be_a(Bitcoin::Message::VerAck)
      end
    end
  end

end