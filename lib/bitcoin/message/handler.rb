module Bitcoin
  module Message

    # Default P2P message handler.
    class Handler

      attr_reader :logger
      attr_reader :conn

      def initialize(conn, logger = Bitcoin::Logger.create(:parser))
        @conn = conn
        @logger = logger
      end

      # handle p2p message.
      def handle(message)
        logger.info "handle message #{message.bth}"
        begin
          parse(message)
        rescue Error => e
          logger.error("invalid header magic. #{e.message}")
          conn.close
        end
      end

      private

      def parse(message)
        command, payload, rest = parse_header(message)
        handle_command(command, payload)
        parse(rest) if rest && rest.bytesize > 0
      end

      def parse_header(message)
        head_magic = Bitcoin.chain_params.magic_head
        raise Error, "invalid message header. message = #{message}" if message.nil? || message.size < HEADER_SIZE

        magic, command, length, checksum = message.unpack('a4A12Va4')
        raise Error, "invalid header magic. #{magic.bth}" unless magic.bth == head_magic

        payload = message[HEADER_SIZE...(HEADER_SIZE + length)]
        raise Error, "header checksum mismatch. #{checksum.bth}" unless Bitcoin.double_sha256(payload)[0...4] == checksum

        rest = message[(HEADER_SIZE + length)..-1]
        [command, payload, rest]
      end

      def handle_command(command, payload)
        logger.info("process command #{command}. payload = #{payload.bth}")
        case command
        when Version::COMMAND
          on_version(Version.parse_from_payload(payload))
        when VerAck::COMMAND
          on_ver_ack
        when Addr::COMMAND
          on_addr(Addr.parse_from_payload(payload))
        when SendHeaders::COMMAND
          on_send_headers
        when FeeFilter::COMMAND
          on_fee_filter(FeeFilter.parse_from_payload(payload))
        when Ping::COMMAND
          on_ping(Ping.parse_from_payload(payload))
        when Pong::COMMAND
          on_pong(Pong.parse_from_payload(payload))
        when GetHeaders::COMMAND
          on_get_headers(GetHeaders.parse_from_payload(payload))
        when Block::COMMAND
          on_block(Block.parse_from_payload(payload))
        when Tx::COMMAND
          on_tx(Tx.parse_from_payload(payload))
        when NotFound::COMMAND
          on_not_found(NotFound.parse_from_payload(payload))
        when MemPool::COMMAND
          on_mem_pool
        else
          conn.close("with command #{command}")
        end
      end

      def on_version(version)
        logger.info("receive version message. #{version.to_json}")
        conn.send_data(VerAck.new.to_pkt)
      end

      def on_ver_ack
        logger.info('receive verack message.')
        conn.handshake_done
      end

      def on_addr(addr)
        logger.info("receive addr message. #{addr.to_json}")
        # TODO
      end

      def on_send_headers
        logger.info('receive sendheaders message.')
        conn.sendheaders = true
      end

      def on_fee_filter(fee_filter)
        logger.info("receive feefilter message. #{fee_filter.to_json}")
        conn.fee_rate = fee_filter.fee_rate
      end

      def on_ping(ping)
        logger.info("receive ping message. #{ping.to_json}")
        conn.send_data(ping.to_response)
      end

      def on_pong(pong)
        logger.info("receive pong message. #{pong.to_json}")
        # TODO calculate response
      end

      def on_get_headers(headers)
        logger.info("receive getheaders message. #{headers.to_json}")
        # TODO
      end

      def on_block(block)
        logger.info("receive block message. #{block.to_json}")
        # TODO
      end

      def on_tx(tx)
        logger.info("receive tx message. #{tx.to_json}")
        # TODO
      end

      def on_not_found(not_found)
        logger.info("receive notfound message. #{not_found.to_json}")
        # TODO
      end

      def on_mem_pool
        logger.info('receive mempool message.')
        # TODO return mempool tx
      end

    end
  end
end