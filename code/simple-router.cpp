/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  fprintf(stderr, "\n-----------------handlePacket-------------------\n");
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

  print_hdrs(packet);
  fprintf(stderr, "-----------------------------------\n\n");

  // Parse ethernet header
  ethernet_hdr *eth_hdr = (ethernet_hdr *)packet.data();
  
  /**
   * Ethernet frames not destined to the router, i.e.,
   * (a) neither the corresponding MAC address of the interface
   * (b) nor broadcast MAC address (ff:ff:ff:ff:ff:ff)
   */
  Buffer eth_dhost = Buffer(eth_hdr->ether_dhost, eth_hdr->ether_dhost + ETHER_ADDR_LEN);
  auto dst_iface = findIfaceByMac(eth_dhost);
  if (dst_iface == nullptr && eth_dhost != ETHER_ADDR_BROADCAST) {
    std::cerr << "Received packet, not destined to the router, ignoring" << std::endl;
    return;
  }
  /**
   * ignore Ethernet frames other than ARP and IPv4
   */
  auto eth_type = ntohs(eth_hdr->ether_type);
  if(eth_type == ethertype_arp) {
    handleArp((arp_hdr *)(packet.data() + sizeof(ethernet_hdr)));
  } else if (eth_type == ethertype_ip) {
    Buffer ip_datagram = Buffer(packet.begin() + sizeof(ethernet_hdr), packet.end());
    handleIp(ip_datagram, inIface);
  } else {
    std::cerr << "Received packet, not ARP or IP, ignoring" << std::endl;
    return;
  }

}

void SimpleRouter::handleArp(const arp_hdr* arp_h) {
  /**
   * ARP request
   * 1. check if the destination IP address is in the router
   * 2. if yes, send ARP reply with the MAC address of the interface
   * 3. if no, ignore
   */
  if(ntohs(arp_h->arp_op) == arp_op_request) {
    auto dst_iface = findIfaceByIp(arp_h->arp_tip);
    if(dst_iface == nullptr) {
      std::cerr << "(Invalid) Received ARP request for " << ipToString(arp_h->arp_tip) << ", not in the router, ignoring" << std::endl;
      return;
    }
    fprintf(stderr, "(Valid) Received ARP request, destination interface: %s\n %s\n %s\n", dst_iface->name.c_str(), ipToString(dst_iface->ip).c_str(), macToString(dst_iface->addr).c_str());

    // Respond to ARP request
    Buffer response = Buffer(sizeof(ethernet_hdr) + sizeof(arp_hdr));
    // Ethernet header
    ethernet_hdr *eth_hdr_res = (ethernet_hdr *)response.data();
    eth_hdr_res->ether_type = htons(ethertype_arp);
    memcpy(eth_hdr_res->ether_dhost, arp_h->arp_sha, ETHER_ADDR_LEN);
    memcpy(eth_hdr_res->ether_shost, dst_iface->addr.data(), ETHER_ADDR_LEN);
    // ARP header
    arp_hdr *arp_hdr_res = (arp_hdr *)(response.data() + sizeof(ethernet_hdr));
    arp_hdr_res->arp_hrd = htons(arp_hrd_ethernet);
    arp_hdr_res->arp_pro = htons(ethertype_ip);
    arp_hdr_res->arp_hln = ETHER_ADDR_LEN;
    arp_hdr_res->arp_pln = sizeof(uint32_t);
    arp_hdr_res->arp_op = htons(arp_op_reply);
    memcpy(arp_hdr_res->arp_sha, dst_iface->addr.data(), ETHER_ADDR_LEN);
    arp_hdr_res->arp_sip = dst_iface->ip;
    memcpy(arp_hdr_res->arp_tha, arp_h->arp_sha, ETHER_ADDR_LEN);
    arp_hdr_res->arp_tip = arp_h->arp_sip;
    
    // 查询路由表，决定从哪个接口发出去
    RoutingTableEntry routing_entry;
    try {
      routing_entry = getRoutingTable().lookup(arp_hdr_res->arp_tip);
    } catch(...) {
      std::cerr << "Received ARP request, routing entry not found, ignoring" << std::endl;
      return;
    }
    auto outIface = routing_entry.ifName;
    fprintf(stderr, "Send ARP reply to %s\n", outIface.c_str());
    sendPacket(response, outIface);
    return;
  }
  /**
   * ARP reply
   * 1. record IP-MAC mapping in ARP cache
   * 2. send out all corresponding enqueued packets
   */
  else if(ntohs(arp_h->arp_op) == arp_op_reply) {
    Buffer s_mac(arp_h->arp_sha, arp_h->arp_sha + ETHER_ADDR_LEN);
    // insertArpEntry返回与该IP对应的请求队列，且将该IP-MAC映射插入ARP缓存
    auto arp_request = m_arp.insertArpEntry(s_mac, arp_h->arp_sip);
    if(arp_request != nullptr) {
      // 发送所有等待该IP-MAC映射的数据包
      for(auto p : arp_request->packets) {
        // 更新以太网帧头
        ethernet_hdr *eth_h = (ethernet_hdr *)p.packet.data();
        memcpy(eth_h->ether_dhost, s_mac.data(), ETHER_ADDR_LEN);

        sendPacket(p.packet, p.iface);
      }
      // 删除该IP对应的请求队列
      m_arp.removeRequest(arp_request);
    }
    return;
  }
  else {
    std::cerr << "Received ARP packet, not request or reply, ignoring" << std::endl;
    return;
  }
}

void SimpleRouter::handleIp(const Buffer& datagram, const std::string& inIface) {
  ip_hdr *ip_h = (ip_hdr *)(datagram.data());
  icmp_hdr *icmp_h = (icmp_hdr *)(datagram.data() + sizeof(ip_hdr));
  
  // 检查IP包的最小长度
  if(datagram.size() < sizeof(ip_hdr)) {
    std::cerr << "Received IP packet, but header is incomplete, ignoring" << std::endl;
    return;
  }
  // 检查IP包的校验和
  uint16_t old_sum = ip_h->ip_sum;
  ip_h->ip_sum = 0; // NOTE: 校验和字段置0
  if(old_sum != cksum(ip_h, sizeof(ip_hdr))) {
    std::cerr << "Received IP packet, but checksum is incorrect, ignoring" << std::endl;
    return;
  }

  
  // 路由器直接丢弃TTL为0或1的IP数据报，发送ICMP超时差错报文
  // 参考https://blog.csdn.net/weixin_33881753/article/details/92789295
  // if(ip_h->ip_ttl <= 1) {
  //   // TODO: 发送ICMP超时差错报文
  //   std::cerr << "Received IP packet, TTL is 0 or 1, respond ICMP(11,0)" << std::endl;
  //   // 去除以太网帧头
  //   sendIcmpType3(datagram, inIface, 11, 0); // Time Exceeded
  //   return;
  // }

  // 检查IP包的目的IP地址是否为路由器的IP地址
  auto dst_iface = findIfaceByIp(ip_h->ip_dst);
  
  /**
   * ---------------------------------------------
   * (1) destined to the router
   *   (a) ICMP echo request & checksum valid -> respond ICMP echo reply
   *   (b) TCP/UDP -> respond ICMP port unreachable 
   * ---------------------------------------------
  */
  if(dst_iface != nullptr) {
    // (a) IP Protocol不是ICMP, 返回端口不可达ICMP报文
    if(ip_h->ip_p != ip_protocol_icmp) { 
      if(ip_h->ip_p == ip_protocol_tcp || ip_h->ip_p == ip_protocol_udp) {
        std::cerr << "Received IP packet, with TCP/UDP payload, respond ICMP(3,3)" << std::endl;
        sendIcmpType3(datagram, inIface, 3, 3); // Port Unreachable
      } else {
        std::cerr << "Received IP packet, not ICMP, TCP or UDP, ignoring" << std::endl;
      }
      return;
    }
    // (b) 收到Echo请求，返回Echo应答
    if(icmp_h->icmp_type == 8 && icmp_h->icmp_code == 0) {
      std::cerr << "Received IP packet, ICMP Echo request, respond ICMP(0,0)" << std::endl;
      sendIcmpEchoReply(datagram, inIface); // Echo Reply
    } else {
      std::cerr << "Received IP packet, not ICMP Echo request, ignoring" << std::endl;
    }
    return;
  }
  
  /**
   * -----------------------------------------
   * (2) datagrams to be forwarded
   * Find next-hop IP address and forward the packet
   * Decrement TTL and recompute the checksum
   * ----------------------------------------- 
  */
  
  Buffer out_datagram = Buffer(datagram);
  // IP header
  ip_hdr *out_ip_h = (ip_hdr *)(out_datagram.data());
  out_ip_h->ip_ttl -= 1; // TTL减1
  out_ip_h->ip_sum = 0;
  out_ip_h->ip_sum = cksum(out_ip_h, sizeof(ip_hdr)); // 重新计算校验和

  // sendIpDatagram(out_datagram, inIface);
  if(ip_h->ip_ttl != 0) {
    sendIpDatagram(out_datagram, inIface);  // TTL不为0，转发IP数据报
  } else {
    fprintf(stderr, "Aboout to forward packet, TTL is 0, respond ICMP(11,0)");
    sendIcmpType3(datagram, inIface, 11, 0); // Time Exceeded
  }

  return;
}

void SimpleRouter::sendIpDatagram(const Buffer& datagram, const std::string& inIface) {
  Buffer frame = Buffer(datagram);
  frame.insert(frame.begin(), sizeof(ethernet_hdr), 0);
  ethernet_hdr *eth_h = (ethernet_hdr *)frame.data();
  ip_hdr *ip_h = (ip_hdr *)(frame.data() + sizeof(ethernet_hdr));
  // 查找路由表，找到出接口
  RoutingTableEntry routing_entry;
  try {
    routing_entry = getRoutingTable().lookup(ip_h->ip_dst);
  } catch(...) {
    fprintf(stderr, "sendIpDatagram: routing entry not found\n");
    return;
  }
  auto outIface = findIfaceByName(routing_entry.ifName);
  if(outIface == nullptr) {
    fprintf(stderr, "sendIpDatagram: failed to find iface by name\n");
    return;
  }

  eth_h->ether_type = htons(ethertype_ip);
  memcpy(eth_h->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);

  // 查询ARP缓存，找到下一跳的MAC地址
  auto arp_entry = m_arp.lookup(ip_h->ip_dst);
  if(arp_entry == nullptr) {
    // 添加到ARP请求队列
    m_arp.queueRequest(ip_h->ip_dst, frame, outIface->name, inIface);
    return;
  }
  
  memcpy(eth_h->ether_dhost, arp_entry->mac.data(), ETHER_ADDR_LEN);
  
  sendPacket(frame, outIface->name);
}

void SimpleRouter::sendIcmpType3(const Buffer& inDatagram, const std::string& inIface, uint8_t type, uint8_t code) {
  Buffer out_datagram = Buffer(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
  ip_hdr *ip_h = (ip_hdr *)out_datagram.data();
  icmp_t3_hdr *icmp_h = (icmp_t3_hdr *)(out_datagram.data() + sizeof(ip_hdr));

  // ICMP header
  icmp_h->icmp_type = type;
  icmp_h->icmp_code = code;
  icmp_h->unused = 0;
  icmp_h->next_mtu = 0;
  memcpy(icmp_h->data, inDatagram.data(), ICMP_DATA_SIZE);
  icmp_h->icmp_sum = 0;
  icmp_h->icmp_sum = cksum(icmp_h, sizeof(icmp_t3_hdr));
  
  // IP header
  ip_h->ip_v = 4;
  ip_h->ip_hl = 5;
  ip_h->ip_tos = 0;
  ip_h->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_t3_hdr));
  ip_h->ip_id = htons((uint16_t)rand());
  ip_h->ip_off = htons(IP_DF);
  ip_h->ip_ttl = 64;
  ip_h->ip_p = ip_protocol_icmp;
  ip_h->ip_src = findIfaceByName(inIface)->ip;
  ip_h->ip_dst = ((ip_hdr *)(inDatagram.data()))->ip_src;
  ip_h->ip_sum = 0;
  ip_h->ip_sum = cksum(ip_h, sizeof(ip_hdr));
  
  sendIpDatagram(out_datagram, inIface);
}

void SimpleRouter::sendIcmpEchoReply(const Buffer& inDatagram, const std::string& inIface) {
  // Buffer outDatagram = Buffer(sizeof(ip_hdr) + sizeof(icmp_echo_hdr));
  Buffer outDatagram = Buffer(inDatagram);
  ip_hdr *ip_h = (ip_hdr *)outDatagram.data();
  icmp_echo_hdr *icmp_h = (icmp_echo_hdr *)(outDatagram.data() + sizeof(ip_hdr));

  // ICMP header
  icmp_h->icmp_type = 0;  // only type change from 8 to 0
  icmp_h->icmp_code = 0;
  icmp_h->icmp_id = ((icmp_echo_hdr *)(inDatagram.data() + sizeof(ip_hdr)))->icmp_id;
  icmp_h->icmp_seq = ((icmp_echo_hdr *)(inDatagram.data() + sizeof(ip_hdr)))->icmp_seq;
  icmp_h->icmp_sum = 0;
  // icmp_h->icmp_sum = cksum(icmp_h, sizeof(icmp_echo_hdr)); 
  // 校验和需要计算整个ICMP报文，包括ICMP头和ICMP数据
  icmp_h->icmp_sum = cksum(outDatagram.data() + sizeof(ip_hdr), outDatagram.size() - sizeof(ip_hdr));

  // IP header
  ip_h->ip_v = 4;
  ip_h->ip_hl = 5;
  ip_h->ip_tos = 0;
  // ip_h->ip_len = htons(sizeof(ip_hdr) + sizeof(icmp_echo_hdr));
  ip_h->ip_len = htons(outDatagram.size());
  ip_h->ip_id = htons((uint16_t)rand());
  ip_h->ip_off = htons(IP_DF);
  ip_h->ip_ttl = 64;
  ip_h->ip_p = ip_protocol_icmp;
  ip_h->ip_src = findIfaceByName(inIface)->ip;
  ip_h->ip_dst = ((ip_hdr *)(inDatagram.data()))->ip_src;
  ip_h->ip_sum = 0;
  ip_h->ip_sum = cksum(ip_h, sizeof(ip_hdr));

  sendIpDatagram(outDatagram, inIface);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  fprintf(stderr, "\n-----------------sendPacket(%s)-------------------\n", outIface.c_str());
  print_hdrs(packet);
  fprintf(stderr, "-----------------------------------\n\n");
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
