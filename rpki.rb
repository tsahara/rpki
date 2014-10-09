#!/usr/bin/env ruby

require 'ipaddr'
require 'socket'
require 'time'

require 'serverengine'

module RPKI
  class RouterProtocol
    POLLINTERVAL = 1800      # 30min

    def initialize host, logger
      @host = host
      @session_id = 0
      @last_serial = 0
      #@list = PrefixList.new
      @sock = nil

      @logger = logger
    end

    def close
      @sock.close if @sock
    end

    def connect
      f = File.open("log", "w")
      TCPSocket.open(@host, 323) { |sock|
        @sock = sock

        @logger.info "Reset Query"
        sock.write ResetQueryPDU.new.to_bytes

        bytes = ""
        while true
          a = IO.select([sock], [], [], POLLINTERVAL)

          if a
            bytes += sock.recv(1024)
            while pdu = PDU.from_bytes(bytes)
              #p pdu
              timestamp = Time.now.iso8601
              if pdu.is_a? IPv4PrefixPDU or pdu.is_a? IPv6PrefixPDU
                if pdu.flags & 1
                  flag = "+"
                else
                  flag = "-"
                end
                # "1111:2222:3333::".size = 16
                f.printf "%s %-20s %3u - %3u  as%u\n", flag, pdu.prefix.to_s, pdu.prefixlen, pdu.maxlen, pdu.asn
              elsif pdu.is_a? CacheResponsePDU
                @logger.info "Cache Response"
                @session_id = pdu.session_id
              elsif pdu.is_a? EndOfDataPDU
                @logger.info "End of Data"
                @last_serial = pdu.serial
              else
                @logger.error "Unexpected #{pdu.class.to_s}"
              end

              bytes = bytes[pdu.length..-1]
            end
          else
            # timeout
            @logger.info "send Serual Query #{@last_serial}"
            sock.send SerialQueryPDU.new(@session_id, @last_serial).to_bytes, 0
          end
        end
      }
      @sock = nil
    end

    class PDU
      def initialize ver, type, sid, len
        @version    = ver
        @type       = type
        @session_id = sid
        @length     = len
      end

      attr_reader :version, :type, :session_id, :length
      
      def self.from_bytes bytes
        return nil if bytes.length < 8

        ver, type, sid, len = bytes.unpack "CCnN"
        return nil if bytes.length < len

        case type
        when 0
          cls = SerialNotifyPDU
        when 1
          cls = SerialQueryPDU
        when 3
          cls = CacheResponsePDU
        when 4
          cls = IPv4PrefixPDU
        when 6
          cls = IPv6PrefixPDU
        when 7
          cls = EndOfDataPDU
        else
          raise "unknown type #{type}"
        end
        pdu = cls.new(ver, type, sid, len)
        pdu.parse bytes[8..-1]
        pdu
      end
    end

    class SerialNotifyPDU < PDU
      attr_reader :serial

      def parse payload
        @serial = payload.unpack("N")[0]
      end
    end

    class SerialQueryPDU < PDU
      def initialize session_id, serial
        super(0, 1, session_id, 12)
        @session_id = session_id
        @serial = serial
      end

      def parse payload
        @serial = payload.unpack("N")[0]
      end

      def to_bytes
        [ 0, 1, @session_id, 12, @serial ].pack "CCnNN"
      end
    end

    class CacheResponsePDU < PDU
      def parse payload
        # empty
      end
    end

    class IPv4PrefixPDU < PDU
      attr_reader :flags, :prefixlen, :maxlen, :prefix, :asn

      def parse payload
        @flags, @prefixlen, @maxlen, _, prefix, @asn = payload.unpack "CCCCa4N"
        @prefix = IPAddr.new_ntoh(prefix).mask(@prefixlen)
      end
    end

    class IPv6PrefixPDU < PDU
      attr_reader :flags, :prefixlen, :maxlen, :prefix, :asn

      def parse payload
        @flags, @prefixlen, @maxlen, _, prefix, @asn = payload.unpack "CCCCa16N"
        @prefix = IPAddr.new_ntoh(prefix).mask(@prefixlen)
      end
    end

    class ResetQueryPDU < PDU
      def initialize
        super(0, 2, 0, 8)
      end

      def to_bytes
        [ 0, 2, 0, 8 ].pack "CCnN"
      end
    end

    class EndOfDataPDU < PDU
      attr_reader :serial

      def parse payload
        @serial = payload.unpack("N")[0]
      end
    end
  end
end

module RPKI
  module Daemon
    def run
      logger.info "run"
      @rpki = RPKI::RouterProtocol.new "roa1.mfeed.ad.jp", logger
      #rpki = RPKI::RouterProtocol.new "192.41.192.218", logger
      @rpki.connect
      logger.info "done"
    end

    def stop
      logger.info "stop"
      @rpki.close
    end
  end
end

se = ServerEngine.create(nil, RPKI::Daemon, {
  :daemonize => true,
  :log => 'myserver.log',
  :pid_path => 'myserver.pid',
})
se.run
