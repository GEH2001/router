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

#ifndef SIMPLE_ROUTER_SIMPLE_ROUTER_HPP
#define SIMPLE_ROUTER_SIMPLE_ROUTER_HPP

#include "arp-cache.hpp"
#include "routing-table.hpp"
#include "core/protocol.hpp"
#include "core/interface.hpp"

#include "pox.hpp"

namespace simple_router {

class SimpleRouter
{
public:

  SimpleRouter();

  /**
   * IMPLEMENT THIS METHOD
   *
   * This method is called each time the router receives a packet on
   * the interface.  The packet buffer \p packet and the receiving
   * interface \p inIface are passed in as parameters. The packet is
   * complete with ethernet headers.
   * @param packet 以太网帧
   * @param inIface 帧的入接口
   */
  void
  handlePacket(const Buffer& packet, const std::string& inIface);

  /**
   * USE THIS METHOD TO SEND PACKETS
   *
   * Call this method to send packet \p packt from the router on interface \p outIface
   */
  void
  sendPacket(const Buffer& packet, const std::string& outIface);
  
  /**
   * Handle ARP packets, used in `handlePacket` 
   */
  void handleArp(const arp_hdr* arp_h);

  /**
   * Handle IP packets, used in `handlePacket`
   * @param datagram IP数据报(ether payload)
   * @param inIface 帧的入接口
   */
  void handleIp(const Buffer& datagram, const std::string& inIface);

  /**
   * 将IP数据报封装为以太网帧, 调用sendPacket方法发送
   * @param datagram 要发送的IP数据报
   */
  void sendIpDatagram(const Buffer& datagram);

  /**
   * 发送 Time Exceeded(11,0) 和 Port Unreachable(3,3) 的ICMP报文
   * 构建ICMP报文, 调用sendIpDatagram方法发送
   * @param inDatagram 帧携带的IP数据报
   * @param inIface 帧的入接口
   * @param type ICMP类型
   * @param code ICMP代码
   */
  void sendIcmpType3(const Buffer& inDatagram, const std::string& inIface, uint8_t type, uint8_t code);

  /**
   * 发送 Echo Reply(0,0) 的ICMP报文
   * 构建ICMP报文, 调用sendIpDatagram方法发送
   * @param inDatagram 帧携带的IP数据报
   * @param inIface 帧的入接口
   */
  void sendIcmpEchoReply(const Buffer& inDatagram, const std::string& inIface);
  
  /**
   * Load routing table information from \p rtConfig file
   */
  bool
  loadRoutingTable(const std::string& rtConfig);

  /**
   * Load local interface configuration
   */
  void
  loadIfconfig(const std::string& ifconfig);

  /**
   * Get routing table
   */
  const RoutingTable&
  getRoutingTable() const;

  /**
   * Get ARP table
   */
  const ArpCache&
  getArp() const;

  /**
   * Print router interfaces
   */
  void
  printIfaces(std::ostream& os);

  /**
   * Reset ARP cache and interface list (e.g., when mininet restarted)
   */
  void
  reset(const pox::Ifaces& ports);

  /**
   * Find interface based on interface's IP address
   */
  const Interface*
  findIfaceByIp(uint32_t ip) const;

  /**
   * Find interface based on interface's MAC address
   */
  const Interface*
  findIfaceByMac(const Buffer& mac) const;

  /**
   * Find interface based on interface's name
   */
  const Interface*
  findIfaceByName(const std::string& name) const;

private:
  ArpCache m_arp;
  RoutingTable m_routingTable;
  std::set<Interface> m_ifaces;
  std::map<std::string, uint32_t> m_ifNameToIpMap;

  friend class Router;
  pox::PacketInjectorPrx m_pox;
};

inline const RoutingTable&
SimpleRouter::getRoutingTable() const
{
  return m_routingTable;
}

inline const ArpCache&
SimpleRouter::getArp() const
{
  return m_arp;
}

} // namespace simple_router

#endif // SIMPLE_ROUTER_SIMPLE_ROUTER_HPP
