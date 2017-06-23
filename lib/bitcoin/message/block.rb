module Bitcoin
  module Message

    # block message
    # https://bitcoin.org/en/developer-reference#block
    class Block < Base

      attr_accessor :header
      attr_accessor :transactions

      def initialize(header, transactions = [])
        @header = header
        @transactions = transactions
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        header = Bitcoin::BlockHeader.parse_from_payload(buf.read(80))
        transactions = []
        unless buf.eof?
          tx_count = Bitcoin.unpack_var_int_from_io(buf)
          tx_count.times do
            transactions << Bitcoin::Tx.parse_from_payload(buf)
          end
        end
        new(header, transactions)
      end

      def command
        'block'
      end

      def to_payload

      end

    end

  end
end
