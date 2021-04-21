
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Net.NetworkInformation;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Transport;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Ethernet;
using System.Linq;
using PcapDotNet.Base;
using PcapDotNet.Packets;

namespace ICMPTraceroute
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void btnApply_MouseMove(object sender, MouseEventArgs e)
        {
            
        }

        private void btnApply_Click(object sender, RoutedEventArgs e)
        {            

            /*
             var route = TraceRoute.GetTraceRoute(tbDestinationIP.Text);

             foreach (var step in route)
             {
                 lbReplays.Items.Add(step.Address);             
             }
             */
        }

        private void btnClear_Click(object sender, RoutedEventArgs e)
        {
            lbReplays.Items.Clear();
        }

        /// <summary>
        /// This function build an ICMP over IPv4 over Ethernet packet.
        /// </summary>
        private static Packet BuildIcmpPacket()
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress("01:01:01:01:01:01"),
                    Destination = new MacAddress("02:02:02:02:02:02"),
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            IpV4Layer ipV4Layer =
                new IpV4Layer
                {
                    Source = new IpV4Address("1.2.3.4"),
                    CurrentDestination = new IpV4Address("11.22.33.44"),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = IpV4Options.None,
                    Protocol = null, // Will be filled automatically.
                    Ttl = 100,
                    TypeOfService = 0,
                };

            IcmpEchoLayer icmpLayer =
                new IcmpEchoLayer
                {
                    Checksum = null, // Will be filled automatically.
                    Identifier = 456,
                    SequenceNumber = 800,
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, icmpLayer);

            return builder.Build(DateTime.Now);
        }
    }

    /*
    public static class TraceRoute
    {
        public static IEnumerable<PingReply> GetTraceRoute(string hostnameOrIp)
        {
            // Initial variables
            var limit = 1000;
            var buffer = new byte[32];
            var pingOpts = new PingOptions(1, true);
            var ping = new Ping();

            // Result holder.
            PingReply result = null;

            do
            {
                result = ping.Send(hostnameOrIp, 4000, buffer, pingOpts);
                pingOpts = new PingOptions(pingOpts.Ttl + 1, pingOpts.DontFragment);

                if (result.Status != IPStatus.TimedOut)
                {
                    yield return result;
                }
            }
            while (result.Status != IPStatus.Success && pingOpts.Ttl < limit);
        }
    }
    */
}

/*

namespace PcapDotNet.Packets.Icmp
{
    public sealed class IcmpTraceRouteLayer : IcmpLayer
    {

        public IcmpCodeTraceRoute Code { get; set; }

        public ushort Identification { get; set; }

        public ushort OutboundHopCount { get; set; }

        public ushort ReturnHopCount { get; set; }

        public uint OutputLinkSpeed { get; set; }

        public uint OutputLinkMaximumTransmissionUnit { get; set; }

        public override IcmpMessageType MessageType
        {
            get { return IcmpMessageType.TraceRoute; }
        }

        protected override int PayloadLength
        {
            get { return IcmpTraceRouteDatagram.PayloadLength; }
        }

        public override byte CodeValue
        {
            get { return (byte)Code; }
        }

        protected override uint Variable
        {
            get { return (uint)(Identification << 16); }
        }

        protected override void WritePayload(byte[] buffer, int offset) => IcmpTraceRouteDatagram.WriteHeaderAdditional(buffer, offset, OutboundHopCount, ReturnHopCount, OutputLinkSpeed, OutputLinkMaximumTransmissionUnit);

        protected override bool EqualPayload(IcmpLayer other)
        {
            return EqualPayload(other as IcmpTraceRouteLayer);
        }

        private bool EqualPayload(IcmpTraceRouteLayer other)
        {
            return other != null &&
                   OutboundHopCount == other.OutboundHopCount &&
                   ReturnHopCount == other.ReturnHopCount &&
                   OutputLinkSpeed == other.OutputLinkSpeed &&
                   OutputLinkMaximumTransmissionUnit == other.OutputLinkMaximumTransmissionUnit;
        }
    }
}
*/