#!/usr/bin/env ruby

require 'ipaddr'
require 'socket'

module RPKI
  class RouterProtocol
    def initialize host
      @host = host
    end

    def connect
      TCPSocket.open(@host, 323) { |sock|
        sock.write ResetQueryPDU.new.to_bytes

        bytes = ""
        while true
          puts "#{bytes.size} bytes available"
          pdu = PDU.from_bytes(bytes)
          if pdu
            p pdu
            bytes = bytes[pdu.length..-1]
          else
            bytes += sock.recv(1024)
          end
        end
      }
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

    class CacheResponsePDU < PDU
      def parse payload
        # empty
      end
    end

    class IPv4PrefixPDU < PDU
      def parse payload
        @flags, @prefixlen, @maxlen, _, prefix, @asn = payload.unpack "CCCCa4N"
        @prefix = IPAddr.new_ntoh(prefix).mask(@prefixlen)
      end
    end

    class IPv6PrefixPDU < PDU
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
      def parse payload
        @serial = payload.unpack "N"
      end
    end
  end
end


rpki = RPKI::RouterProtocol.new "roa1.mfeed.ad.jp"
rpki.connect
