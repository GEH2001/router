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
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

  print_hdrs(packet);

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
  auto eth_type = eth_hdr->ether_type;
  if(eth_type == ethertype_arp) {
    handleArp((arp_hdr *)(packet.data() + sizeof(ethernet_hdr)));
  } else if (eth_type == ethertype_ip) {
    handleIPPacket(packet, inIface);
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
    auto outIface = getRoutingTable().lookup(arp_hdr_res->arp_tip).ifName;
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
