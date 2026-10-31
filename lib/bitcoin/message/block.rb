module Bitcoin
  module Message

    # block message
    # https://bitcoin.org/en/developer-reference#block
    class Block < Base

      attr_accessor :header
      attr_accessor :transactions
      attr_accessor :use_segwit

      COMMAND = 'block'

      def initialize(header, transactions = [], use_segwit = false)
        @header = header
        @transactions = transactions
        @use_segwit = use_segwit
      end

      def self.parse_from_payload(payload)
        buf = StringIO.new(payload)
        header = Bitcoin::BlockHeader.parse_from_payload(Bitcoin.read_exact(buf, 80))
        # A block message always carries its tx count, which may be 0 only in a block nobody can produce.
        tx_count = Bitcoin.unpack_var_int_from_io(buf)
        transactions = tx_count.times.map { Bitcoin::Tx.parse_from_payload(buf) }
        new(header, transactions)
      end

      def to_payload
        header.to_payload << Bitcoin.pack_var_int(transactions.size) <<
          transactions.map{|t|use_segwit ? t.to_payload : t.serialize_old_format}.join
      end

      # generate Bitcoin::Block object.
      def to_block
        Bitcoin::Block.new(header, transactions)
      end

    end

  end
end
