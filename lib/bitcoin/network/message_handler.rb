module Bitcoin
  module Network

    # P2P message handler used by peer connection class.
    module MessageHandler

      # handle p2p message.
      def handle(message)
        peer.last_recv = Time.now.to_i
        peer.bytes_recv += message.bytesize
        begin
          parse(message)
        rescue Bitcoin::Message::Error => e
          logger.error("invalid header magic. #{e.message}")
          close
        end
      end

      def parse(message)
        @message += message
        command, payload, rest = parse_header
        return unless command

        handle_command(command, payload)
        @message = ""
        parse(rest) if rest && rest.bytesize > 0
      end

      def parse_header
        head_magic = Bitcoin.chain_params.magic_head
        return if @message.nil? || @message.size < MESSAGE_HEADER_SIZE

        magic, command, length, checksum = @message.unpack('a4A12Va4')
        raise Bitcoin::Message::Error, "invalid header magic. #{magic.bth}" unless magic.bth == head_magic

        payload = @message[MESSAGE_HEADER_SIZE...(MESSAGE_HEADER_SIZE + length)]
        return if payload.size < length
        raise Bitcoin::Message::Error, "header checksum mismatch. #{checksum.bth}" unless Bitcoin.double_sha256(payload)[0...4] == checksum

        rest = @message[(MESSAGE_HEADER_SIZE + length)..-1]
        [command, payload, rest]
      end

      def handle_command(command, payload)
        logger.info("[#{addr}] process command #{command}.")
        begin
          case command
            when Bitcoin::Message::Version::COMMAND
              on_version(Bitcoin::Message::Version.parse_from_payload(payload))
            when Bitcoin::Message::VerAck::COMMAND
              on_ver_ack
            when Bitcoin::Message::GetAddr::COMMAND
              on_get_addr
            when Bitcoin::Message::Addr::COMMAND
              on_addr(Bitcoin::Message::Addr.parse_from_payload(payload))
            when Bitcoin::Message::SendHeaders::COMMAND
              on_send_headers
            when Bitcoin::Message::FeeFilter::COMMAND
              on_fee_filter(Bitcoin::Message::FeeFilter.parse_from_payload(payload))
            when Bitcoin::Message::Ping::COMMAND
              on_ping(Bitcoin::Message::Ping.parse_from_payload(payload))
            when Bitcoin::Message::Pong::COMMAND
              on_pong(Bitcoin::Message::Pong.parse_from_payload(payload))
            when Bitcoin::Message::GetHeaders::COMMAND
              on_get_headers(Bitcoin::Message::GetHeaders.parse_from_payload(payload))
            when Bitcoin::Message::Headers::COMMAND
              on_headers(Bitcoin::Message::Headers.parse_from_payload(payload))
            when Bitcoin::Message::Block::COMMAND
              on_block(Bitcoin::Message::Block.parse_from_payload(payload))
            when Bitcoin::Message::Tx::COMMAND
              on_tx(Bitcoin::Message::Tx.parse_from_payload(payload))
            when Bitcoin::Message::NotFound::COMMAND
              on_not_found(Bitcoin::Message::NotFound.parse_from_payload(payload))
            when Bitcoin::Message::MemPool::COMMAND
              on_mem_pool
            when Bitcoin::Message::Reject::COMMAND
              on_reject(Bitcoin::Message::Reject.parse_from_payload(payload))
            when Bitcoin::Message::SendCmpct::COMMAND
              on_send_cmpct(Bitcoin::Message::SendCmpct.parse_from_payload(payload))
            when Bitcoin::Message::Inv::COMMAND
              on_inv(Bitcoin::Message::Inv.parse_from_payload(payload))
            else
              logger.warn("unsupported command received. #{command}")
              close("with command #{command}")
          end
        rescue Exception => e
          logger.error("error occurred. #{e.message}")
          logger.error(e.backtrace)
          peer.handle_error(e)
        end
      end

      def send_message(msg)
        logger.info "send message #{msg.class::COMMAND}"
        pkt = msg.to_pkt
        peer.last_send = Time.now.to_i
        peer.bytes_sent = pkt.bytesize
        send_data(pkt)
      end

      def handshake_done
        logger.info 'handshake finished.'
        @connected = true
        post_handshake
      end

      def on_version(version)
        logger.info("receive version message. #{version.build_json}")
        @version = version
        send_message(Bitcoin::Message::VerAck.new)
      end

      def on_ver_ack
        logger.info('receive verack message.')
        handshake_done
      end

      def on_get_addr
        logger.info('receive getaddr message.')
        peer.send_addrs
      end

      def on_addr(addr)
        logger.info("receive addr message. #{addr.build_json}")
        # TODO
      end

      def on_send_headers
        logger.info('receive sendheaders message.')
        @sendheaders = true
      end

      def on_fee_filter(fee_filter)
        logger.info("receive feefilter message. #{fee_filter.build_json}")
        @fee_rate = fee_filter.fee_rate
      end

      def on_ping(ping)
        logger.info("receive ping message. #{ping.build_json}")
        send_message(ping.to_response)
      end

      def on_pong(pong)
        logger.info("receive pong message. #{pong.build_json}")
        if pong.nonce == peer.last_ping_nonce
          peer.last_ping_nonce = nil
          peer.last_pong = Time.now.to_i
        else
          logger.debug "The remote peer sent the wrong nonce (#{pong.nonce})."
        end
      end

      def on_get_headers(headers)
        logger.info('receive getheaders message.')
        # TODO
      end

      def on_headers(headers)
        logger.info('receive headers message.')
        peer.handle_headers(headers)
      end

      def on_block(block)
        logger.info('receive block message.')
        # TODO
      end

      def on_tx(tx)
        logger.info('receive tx message.')
        # TODO
      end

      def on_not_found(not_found)
        logger.info("receive notfound message. #{not_found.build_json}")
        # TODO
      end

      def on_mem_pool
        logger.info('receive mempool message.')
        # TODO return mempool tx
      end

      def on_reject(reject)
        logger.warn("receive reject message. #{reject.build_json}")
        # TODO
      end

      def on_send_cmpct(cmpct)
        logger.info("receive sendcmpct message. #{cmpct.build_json}")
        # TODO if mode is high and version is 1, relay block with cmpctblock message
      end

      def on_inv(inv)
        logger.info('receive inv message.')
        blocks = []
        txs = []
        inv.inventories.each do |i|
          case i.identifier
            when Bitcoin::Message::Inventory::MSG_TX
              txs << i.hash
            when Bitcoin::Message::Inventory::MSG_BLOCK
              blocks << i.hash
            else
              logger.warn("[#{addr}] peer sent unknown inv type: #{i.identifier}")
          end
        end
        logger.info("receive block= #{blocks.size}, txs: #{txs.size}")
        peer.handle_block_inv(blocks) unless blocks.empty?
      end

    end
  end
end