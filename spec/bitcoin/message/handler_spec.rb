require 'spec_helper'

describe Bitcoin::Message::Handler do

  subject {
    mock = double('Connection Mock')
    Bitcoin::Message::Handler.new(mock)
  }

  describe 'handle message' do

    context 'invalid header size' do
      it 'raise message error' do
        expect(subject.conn).to receive(:close).twice
        subject.handle('hoge'.htb)
        subject.handle('')
      end
    end

    context 'invalid header magic' do
      it 'raise message error' do # mainnet magic
        expect(subject.conn).to receive(:close).once
        subject.handle('f9beb4d976657261636b000000000000000000005df6e0e2'.htb)
      end
    end

    context 'invalid header checksum' do
      it 'raise message error' do
        expect(subject.conn).to receive(:close).once
        subject.handle('0b11090776657261636b000000000000000000005df6e0e3'.htb)
      end
    end

    context 'correct header' do
      it 'parse message' do
        expect(subject.conn).not_to receive(:close)
        expect(subject.conn).to receive(:handshake_done).once
        subject.handle('0b11090776657261636b000000000000000000005df6e0e2'.htb)
      end
    end

  end

end
