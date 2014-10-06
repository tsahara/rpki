#!/usr/bin/env ruby

require 'ipaddr'
require 'socket'
require 'time'

module RPKI
  class RouterProtocol
    def initialize host
      @host = host
      @session_id = 0
      @last_serial = 0
      #@list = PrefixList.new
    end

    def connect
      f = File.open("log", "w")
      TCPSocket.open(@host, 323) { |sock|
        sock.write ResetQueryPDU.new.to_bytes

        bytes = ""
        while true
          a = IO.select([sock], [], [], 10)

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
                puts "Cache Response at #{timestamp}"
                @session_id = pdu.session_id
              elsif pdu.is_a? EndOfDataPDU
                puts "End of Data at #{timestamp}"
                @last_serial = pdu.serial
              else
                puts "Unexpected #{pdu.class.to_s}: at #{Time.now.iso8601}"
              end

              bytes = bytes[pdu.length..-1]
            end
          else
            # timeout
            puts "timeout"
            sock.send SerialQueryPDU.new(@session_id, @last_serial).to_bytes, 0
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


rpki = RPKI::RouterProtocol.new "roa1.mfeed.ad.jp"
#rpki = RPKI::RouterProtocol.new "192.41.192.218"
rpki.connect
