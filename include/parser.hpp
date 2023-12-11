#pragma once
#include <stdint.h>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>
#include <unordered_set>
#include <stack>

#include "boost/algorithm/hex.hpp"
#include "isis.hpp"
#include "json.hpp"
#include "utils.hpp"
#include "base64pp.h"

using json = nlohmann::json;

/* aux db, stores graph of connectivity and addional info per node, readable format, key is sys id length 14 separated by - */

struct Router{
       std::map<std::string,std::pair<std::string,std::string>> NEIGHBORS_;
       std::vector<std::string> SUBNETS_;
       std::string AREA_{"_EMPTY_"};
       std::string HOSTNAME_;
};


typedef std::unordered_map<std::string, std::unique_ptr<struct Router>> auxdb;


void parse(std::unordered_map<std::string, std::string>& lsdb, auxdb& auxdb, std::unordered_map<std::string, std::string>& lsdb_raw, const std::string& file_json, const std::string& file_json_raw = std::string()) {
	std::vector<std::string> keys;
	std::ifstream f(file_json);
	std::cout << "Parsing JSON ..." << std::endl;
	json raw = json::parse(f);

        // check if file exists , set bool , bool will be used by mocker to take db 


	json data = raw["isis-database-information"][0]["isis-database"][1]["isis-database-entry"];
	for (const auto& item : data) {
		if (item.find("lsp-id") != item.end()) {
			for (const auto& item2 : item["lsp-id"]) {
				keys.push_back(std::string(item2["data"]));
			}
		}
	}
        #ifdef DEBUG
	std::cout << "Found LSPs: " << keys.size() << std::endl;
        #endif
	if (!keys.size()) {
		throw std::runtime_error(std::string("no LSPs found in json provided"));
	}

	for (int i = 0; i < int(keys.size()); ++i) {
		unsigned short eth_length{0}, pdu_length{0}, remaining_lifetime{0}; 
		uint32_t sequence_number{0};
		// unsigned int our_mt_length{};
		// std::string our_mt_str;
		boost::asio::streambuf checksum_pdu;
		std::ostream os_checksum(&checksum_pdu);
		boost::asio::streambuf tlvs;
		std::ostream os_tlvs(&tlvs);
		boost::asio::streambuf packet;
		std::ostream os(&packet);

		eth_header eth;
		isis_header isis;  
		isis_lsp_header lsp_header;
		isis.pdu_type(l2_lsp);
		isis.length_indicator(27);
		remaining_lifetime = std::stoi(std::string(data[i]["remaining-lifetime"][0]["data"]));
		std::string lsp_id = std::string(data[i]["lsp-id"][0]["data"]);
                #ifdef DEBUG
		std::cout << i << " LSP-ID " << lsp_id << std::endl;
                #endif

                std::unique_ptr<struct Router> temp(new struct Router);
                std::string sys_id_temp = lsp_id.substr(0,14);
                auxdb.insert(std::make_pair(sys_id_temp,std::move(temp)));

		boost::erase_all(lsp_id, ".");
		boost::erase_all(lsp_id, "-");
		sequence_number = htonl(std::stol((std::string(data[i]["sequence-number"][0]["data"]).erase(0, 2)), 0, 16));
		unsigned char sn_temp[4]{0};
		std::memcpy(sn_temp, &sequence_number, 4);
		lsp_header.remaining_lifetime(htons(remaining_lifetime));
		lsp_header.sequence_num(sn_temp);
		unsigned char lsp_id_temp[16]{0}, lsp_id_packed[8]{0};
		std::memcpy(lsp_id_temp, lsp_id.c_str(), lsp_id.size());
		for (int j = 0; j < 16; ++j) {   // not used 
			lsp_id_temp[j] -= 0x30;
		}
		for (int j = 0, k = 0; j < 8 && k < 16; ++j, k += 2) {
			lsp_id_packed[j] = static_cast<unsigned char>(std::stoi(lsp_id.substr(k, 2), 0, 16));
		}
		lsp_header.lsp_id(lsp_id_packed);
		eth_length += (sizeof(isis) + sizeof(lsp_header) + 3);
		pdu_length += (sizeof(isis) + sizeof(lsp_header));
		os_checksum << isis << lsp_header; 
                /* checksum and length here is 0 */
		/* TLVs  */
		/* hostname tlv */
		if (!data[i]["isis-tlv"][0]["hostname-tlv"][0]["hostname"][0]["data"].is_null()) {
			tlv_137 hostname;
			std::string hostname_str = std::string(data[i]["isis-tlv"][0]["hostname-tlv"][0]["hostname"][0]["data"]);
                        auxdb[sys_id_temp].get()->HOSTNAME_ = hostname_str;
			boost::erase_all(hostname_str, ".");
                        #ifdef DEBUG                 
			std::cout << "hostname: " << hostname_str << std::endl;
                        #endif
			hostname.tlv_length(hostname_str.size());
                        hostname.tlv_hostname(hostname_str);
			/*eth_length += sizeof(hostname);
			pdu_length += sizeof(hostname);  hostname is special as
			not fixed, only caped by 255 bytes */
			eth_length += hostname_str.size() + 2;
			pdu_length += hostname_str.size() + 2;
			os_checksum << hostname;
			os_tlvs << hostname;
		}

		/* buffer size tlv */
		if (!data[i]["isis-tlv"][0]["lsp-buffer-size-tlv"][0]["lsp-buffer-size"][0]["data"].is_null()) {
			tlv_14 buffer_size;
			std::string buffer_size_str =
			    std::string(data[i]["isis-tlv"][0]["lsp-buffer-size-tlv"][0]["lsp-buffer-size"][0]["data"]);
			buffer_size.set_size(htons(std::stol(buffer_size_str)));
			eth_length += 4;
			pdu_length += 4;
			os_checksum << buffer_size;
			os_tlvs << buffer_size;
		}

		/* protocols supported tlv */
		if (!data[i]["isis-tlv"][0]["protocols-tlv"][0]["protocol"][0]["data"].is_null()) {
			tlv_129_ext protocols_supported;
			unsigned int index{0}, length{0};
			for (const auto& item : data[i]["isis-tlv"][0]["protocols-tlv"][0]["protocol"]) {
				std::string protocols = std::string(item["data"]);
				if (protocols.compare("Speaks: IP") == 0) {
					length++;
					protocols_supported.nlpid(0xcc, index);
					index++;
				} else if (protocols.compare("Speaks: IPV6") == 0) {
					length++;
					protocols_supported.nlpid(0x8e, index);
					index++;
				} else if (protocols.compare("Speaks: CLNP") == 0) {
					length++;
					protocols_supported.nlpid(0x81, index);
					index++;
				}
			}
			protocols_supported.tlv_length(length);
			eth_length += length + 2;
			pdu_length += length + 2;
			os_checksum << protocols_supported;
			os_tlvs << protocols_supported;
		}

		/* ip address tlv 132 */ // refactor ! -> function , accept string 
		if (!data[i]["isis-tlv"][0]["ipaddress-tlv"][0]["address"][0]["data"].is_null()) {
			tlv_132 ip;
			std::string ip_str = data[i]["isis-tlv"][0]["ipaddress-tlv"][0]["address"][0]["data"];
			unsigned char ip_array[4]{};
			size_t ip_pos = 0;
			std::string ip_delimiter = ".";
			std::string ip_part_1{}, ip_part_2{}, ip_part_3{}, ip_part_4{};
			ip_pos = ip_str.find(ip_delimiter);
			ip_part_1 = ip_str.substr(0, ip_pos);
			ip_str.erase(0, ip_pos + ip_delimiter.length());
			ip_pos = ip_str.find(ip_delimiter);
			ip_part_2 = ip_str.substr(0, ip_pos);
			ip_str.erase(0, ip_pos + ip_delimiter.length());
			ip_pos = ip_str.find(ip_delimiter);
			ip_part_3 = ip_str.substr(0, ip_pos);
			ip_str.erase(0, ip_pos + ip_delimiter.length());
			ip_part_4 = ip_str;
			ip_array[0] = static_cast<unsigned char>(std::stoi(ip_part_1, 0, 10));
			ip_array[1] = static_cast<unsigned char>(std::stoi(ip_part_2, 0, 10));
			ip_array[2] = static_cast<unsigned char>(std::stoi(ip_part_3, 0, 10));
			ip_array[3] = static_cast<unsigned char>(std::stoi(ip_part_4, 0, 10));

			ip.ip_address(ip_array);
			eth_length += 6;
			pdu_length += 6;
			os_checksum << ip;
			os_tlvs << ip;
		}

		/* area address tlv 1 */
		if (!data[i]["isis-tlv"][0]["area-address-tlv"][0]["address"][0]["data"].is_null()) {
			// tlv_1 area;
			tlv_1_ext area;
			std::string area_str = data[i]["isis-tlv"][0]["area-address-tlv"][0]["address"][0]["data"];
                        auxdb[sys_id_temp].get()->AREA_ = area_str;
			boost::erase_all(area_str, ".");
			area.area(area_to_bytes(area_str).get(), area_str.size() / 2);
			area.area_length(area_str.size() / 2);
			area.tlv_length(1 + area_str.size() / 2);
			eth_length += 3 + area_str.size() / 2;
			pdu_length += 3 + area_str.size() / 2;
			os_checksum << area;
			os_tlvs << area;
		}

		/* traffic engineering router id tlv 134 */
		if (!data[i]["isis-tlv"][0]["router-id-tlv"][0]["router-id"][0]["data"].is_null()) {
			tlv_134 te_id;
			std::string te_id_str = data[i]["isis-tlv"][0]["router-id-tlv"][0]["router-id"][0]["data"];
			unsigned char te_id_array[4]{};
			size_t te_id_pos = 0;
			std::string te_id_delimiter = ".";
			std::string te_id_part_1{}, te_id_part_2{}, te_id_part_3{}, te_id_part_4{};
			te_id_pos = te_id_str.find(te_id_delimiter);
			te_id_part_1 = te_id_str.substr(0, te_id_pos);
			te_id_str.erase(0, te_id_pos + te_id_delimiter.length());
			te_id_pos = te_id_str.find(te_id_delimiter);
			te_id_part_2 = te_id_str.substr(0, te_id_pos);
			te_id_str.erase(0, te_id_pos + te_id_delimiter.length());
			te_id_pos = te_id_str.find(te_id_delimiter);
			te_id_part_3 = te_id_str.substr(0, te_id_pos);
			te_id_str.erase(0, te_id_pos + te_id_delimiter.length());
			te_id_part_4 = te_id_str;
			te_id_array[0] = static_cast<unsigned char>(std::stoi(te_id_part_1, 0, 10));
			te_id_array[1] = static_cast<unsigned char>(std::stoi(te_id_part_2, 0, 10));
			te_id_array[2] = static_cast<unsigned char>(std::stoi(te_id_part_3, 0, 10));
			te_id_array[3] = static_cast<unsigned char>(std::stoi(te_id_part_4, 0, 10));

			te_id.ip_address(te_id_array);
			eth_length += 6;
			pdu_length += 6;
			os_checksum << te_id;
			os_tlvs << te_id;
		}
		/* ipv6 interface address tlv 232 */
		if (!data[i]["isis-tlv"][0]["ipv6address-tlv"][0]["address"][0]["data"].is_null()) {
			tlv_232 ipv6_addr;
			std::string ipv6_addr_str = data[i]["isis-tlv"][0]["ipv6address-tlv"][0]["address"][0]["data"];

			IPv6Address ipv6_addr_array;
			ipv6_addr_array.fromString(ipv6_addr_str.c_str());
			ipv6_addr.ip_address(ipv6_addr_array.getAddr());
			eth_length += 18;
			pdu_length += 18;
			os_checksum << ipv6_addr;
			os_tlvs << ipv6_addr;
		}
		/* extended IS reachability  tlv 22 (MT tlv 222) x n neighbors*/
		/* iterating over tlvs 22 */
		for (const auto& item : data[i]["isis-tlv"][0].items()) {
			std::string key_str = std::string(item.key());
			if (key_str.find("reachability-tlv") != std::string::npos && key_str.find("ipv6") == std::string::npos) {
				for (const auto& subindex : data[i]["isis-tlv"][0][key_str].items()) {
					int sub_key_str = std::stoi(subindex.key());
					tlv_22 ext_reach;
					tlv_222 mt_ext_reach;
					unsigned int length{}, sub_length{};
                                        std::string neighbor_map_str;
					bool mt222 = false;

					if (!data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-topology-id"][0]["data"].is_null()) {
						std::string topology_id_str = std::string(
						    data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-topology-id"][0]["data"]);
						if (topology_id_str.compare("IPV4 Unicast") == 0) {
							mt_ext_reach.topology_id(0);
						}
						if (topology_id_str.compare("IPV6 Unicast") == 0) {
							mt_ext_reach.topology_id(2);
						}
						if (topology_id_str.compare("IPV4 Multicast") == 0) {
							mt_ext_reach.topology_id(3);
						}
						if (topology_id_str.compare("IPV6 Multicast") == 0) {
							mt_ext_reach.topology_id(4);
						}

						mt222 = true;
					}
                                       
					/* get reachability tlv processed */
					if (!data[i]["isis-tlv"][0][key_str][sub_key_str]["address-prefix"][0]["data"].is_null()) {
						std::string neighbor_id =
						    std::string(data[i]["isis-tlv"][0][key_str][sub_key_str]["address-prefix"][0]["data"]);
                                                neighbor_map_str = neighbor_id;
						boost::erase_all(neighbor_id, ".");
						boost::erase_all(neighbor_id, "-");
						unsigned char neighbor_id_packed[7]{0};
						for (int j = 0, k = 0; j < 7 && k < 14; ++j, k += 2) {
							neighbor_id_packed[j] =
							    static_cast<unsigned char>(std::stoi(neighbor_id.substr(k, 2), 0, 16));
						}
						ext_reach.neighbor_sysid(neighbor_id_packed);
  
						if (mt222) {
							mt_ext_reach.neighbor_sysid(neighbor_id_packed);
						}
						std::string metric_str =
						    std::string(data[i]["isis-tlv"][0][key_str][sub_key_str]["metric"][0]["data"]);
						unsigned int metric = std::stol(metric_str);
						unsigned char metric_array[3]{};
						metric_array[2] = (metric >> 0) & 0xFF;
						metric_array[1] = (metric >> 8) & 0xFF;
						metric_array[0] = (metric >> 16) & 0xFF;
						ext_reach.metric(metric_array);
						if (mt222) {
							mt_ext_reach.metric(metric_array);
						}
					}

					if (mt222) {
						length += 15;
						eth_length += 15;
						pdu_length += 15;

					} else {
						length += 13;
						eth_length += 13;
						pdu_length += 13;
					}

					/* subTLVs */
					subtlv22_c6 ip_interface_addr;
					subtlv22_c8 neighbor_ip_addr;
					subtlv22_c4 local_remote_ifindex;
					std::vector<subtlv22_c31> adj_sid_vec;
					bool ifindex_found = false;
					bool ip_interface_found = false;
					bool neighbor_ip_found = false;
					bool adj_sid_found = false;


					for (const auto& subitem :
					     data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-reachability-subtlv"].items()) {
						if (!data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-reachability-"
												  "subtlv"][std::stoi(subitem.key())]
							 ["address"][0]["data"]
							     .is_null()) {
							std::string ip_interface_addr_str =
							    data[i]["isis-tlv"][0][key_str][sub_key_str]
								["isis-"
								 "reachability-"
								 "subtlv"][std::stoi(subitem.key())]["address"][0]["data"];
                                                        auxdb[sys_id_temp].get()->NEIGHBORS_[neighbor_map_str.substr(0,14)].first = ip_interface_addr_str;
							unsigned char ip_interface_addr_array[4]{}; // here  
							size_t ip_interface_addr_pos = 0;
							std::string ip_interface_addr_delimiter = ".";
							std::string ip_interface_addr_part_1{}, ip_interface_addr_part_2{},
							    ip_interface_addr_part_3{}, ip_interface_addr_part_4{};
							ip_interface_addr_pos = ip_interface_addr_str.find(ip_interface_addr_delimiter);
							ip_interface_addr_part_1 = ip_interface_addr_str.substr(0, ip_interface_addr_pos);
							ip_interface_addr_str.erase(
							    0, ip_interface_addr_pos + ip_interface_addr_delimiter.length());
							ip_interface_addr_pos = ip_interface_addr_str.find(ip_interface_addr_delimiter);
							ip_interface_addr_part_2 = ip_interface_addr_str.substr(0, ip_interface_addr_pos);
							ip_interface_addr_str.erase(
							    0, ip_interface_addr_pos + ip_interface_addr_delimiter.length());
							ip_interface_addr_pos = ip_interface_addr_str.find(ip_interface_addr_delimiter);
							ip_interface_addr_part_3 = ip_interface_addr_str.substr(0, ip_interface_addr_pos);
							ip_interface_addr_str.erase(
							    0, ip_interface_addr_pos + ip_interface_addr_delimiter.length());
							ip_interface_addr_part_4 = ip_interface_addr_str;
							ip_interface_addr_array[0] =
							    static_cast<unsigned char>(std::stoi(ip_interface_addr_part_1, 0, 10));
							ip_interface_addr_array[1] =
							    static_cast<unsigned char>(std::stoi(ip_interface_addr_part_2, 0, 10));
							ip_interface_addr_array[2] =
							    static_cast<unsigned char>(std::stoi(ip_interface_addr_part_3, 0, 10));
							ip_interface_addr_array[3] =
							    static_cast<unsigned char>(std::stoi(ip_interface_addr_part_4, 0, 10));
							ip_interface_addr.ip_address(ip_interface_addr_array);
							length += 6;
							sub_length += 6;
							eth_length += 6;
							pdu_length += 6;
							ip_interface_found = true;
						}
						if (!data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-reachability-"
												  "subtlv"][std::stoi(subitem.key())]
							 ["neighbor-prefix"][0]["data"]
							     .is_null()) {
							std::string neighbor_ip_addr_str = data[i]["isis-tlv"][0][key_str][sub_key_str]
											       ["isis-"
												"reachability-"
												"subtlv"][std::stoi(subitem.key())]
											       ["neighbor-"
												"prefix"][0]["data"];
                                                        auxdb[sys_id_temp].get()->NEIGHBORS_[neighbor_map_str.substr(0,14)].second = neighbor_ip_addr_str;
							unsigned char neighbor_ip_addr_array[4]{}; // here  
							size_t neighbor_ip_addr_pos = 0;
							std::string neighbor_ip_addr_delimiter = ".";
							std::string neighbor_ip_addr_part_1{}, neighbor_ip_addr_part_2{},
							    neighbor_ip_addr_part_3{}, neighbor_ip_addr_part_4{};
							neighbor_ip_addr_pos = neighbor_ip_addr_str.find(neighbor_ip_addr_delimiter);
							neighbor_ip_addr_part_1 = neighbor_ip_addr_str.substr(0, neighbor_ip_addr_pos);
							neighbor_ip_addr_str.erase(
							    0, neighbor_ip_addr_pos + neighbor_ip_addr_delimiter.length());
							neighbor_ip_addr_pos = neighbor_ip_addr_str.find(neighbor_ip_addr_delimiter);
							neighbor_ip_addr_part_2 = neighbor_ip_addr_str.substr(0, neighbor_ip_addr_pos);
							neighbor_ip_addr_str.erase(
							    0, neighbor_ip_addr_pos + neighbor_ip_addr_delimiter.length());
							neighbor_ip_addr_pos = neighbor_ip_addr_str.find(neighbor_ip_addr_delimiter);
							neighbor_ip_addr_part_3 = neighbor_ip_addr_str.substr(0, neighbor_ip_addr_pos);
							neighbor_ip_addr_str.erase(
							    0, neighbor_ip_addr_pos + neighbor_ip_addr_delimiter.length());
							neighbor_ip_addr_part_4 = neighbor_ip_addr_str;
							neighbor_ip_addr_array[0] =
							    static_cast<unsigned char>(std::stoi(neighbor_ip_addr_part_1, 0, 10));
							neighbor_ip_addr_array[1] =
							    static_cast<unsigned char>(std::stoi(neighbor_ip_addr_part_2, 0, 10));
							neighbor_ip_addr_array[2] =
							    static_cast<unsigned char>(std::stoi(neighbor_ip_addr_part_3, 0, 10));
							neighbor_ip_addr_array[3] =
							    static_cast<unsigned char>(std::stoi(neighbor_ip_addr_part_4, 0, 10));
							neighbor_ip_addr.ip_address(neighbor_ip_addr_array);
							length += 6;
							sub_length += 6;
							eth_length += 6;
							pdu_length += 6;
							neighbor_ip_found = true;

						}
						if (!data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-reachability-"
												  "subtlv"][std::stoi(subitem.key())]
							 ["local-ifindex"][0]["data"]
							     .is_null() &&
						    !data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-reachability-"
												  "subtlv"][std::stoi(subitem.key())]
							 ["remote-ifindex"][0]["data"]
							     .is_null()) {
							std::string local_ifindex_str =
							    std::string(data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-"
														     "reachabil"
														     "ity-"
														     "subtlv"]
									    [std::stoi(subitem.key())]["local-"
												       "ifindex"][0]["data"]);
							std::string remote_ifindex_str =
							    std::string(data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-"
														     "reachabil"
														     "ity-"
														     "subtlv"]
									    [std::stoi(subitem.key())]["remote-"
												       "ifindex"][0]["data"]);
							unsigned int local_ifindex = std::stol(local_ifindex_str);
							unsigned int remote_ifindex = std::stol(remote_ifindex_str);
							unsigned char local_ifindex_array[4]{}, remote_ifindex_array[4]{};
							local_ifindex_array[3] = (local_ifindex >> 0) & 0xFF; // loop to reduce code 
							local_ifindex_array[2] = (local_ifindex >> 8) & 0xFF;
							local_ifindex_array[1] = (local_ifindex >> 16) & 0xFF;
							local_ifindex_array[0] = (local_ifindex >> 24) & 0xFF;

							remote_ifindex_array[3] = (remote_ifindex >> 0) & 0xFF;
							remote_ifindex_array[2] = (remote_ifindex >> 8) & 0xFF;
							remote_ifindex_array[1] = (remote_ifindex >> 16) & 0xFF;
							remote_ifindex_array[0] = (remote_ifindex >> 24) & 0xFF;
							local_remote_ifindex.link_local_id(local_ifindex_array);
							local_remote_ifindex.link_remote_id(remote_ifindex_array);

							length += 10;
							sub_length += 10;
							eth_length += 10;
							pdu_length += 10;
							ifindex_found = true;
						}


						/* sr subtlv */
						if (!data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-reachability-"
												  "subtlv"][std::stoi(subitem.key())]
							 ["p2p-adj-sid-flags"][0]["data"]
							     .is_null()) {
							subtlv22_c31 adj_sid;
							std::string adj_flags = std::string(
							    data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-reachability-subtlv"]
								[std::stoi(subitem.key())]["p2p-adj-sid-flags"][0]["data"]);
							adj_flags.erase(0, 2);
							adj_flags = adj_flags.substr(0, adj_flags.find("("));
							adj_sid.flags(static_cast<unsigned char>(std::stoi(adj_flags, 0, 16)));
							std::string adj_weight = std::string(
							    data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-reachability-subtlv"]
								[std::stoi(subitem.key())]["p2p-adj-sid-weight"][0]["data"]);
							adj_sid.weight(static_cast<unsigned char>(std::stoi(adj_weight, 0, 16)));

							std::string adj_label = std::string(
							    data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-reachability-subtlv"]
								[std::stoi(subitem.key())]["p2p-adj-sid-label"][0]["data"]);
							if (isKthBitSet(adj_sid.flags(), 4) && isKthBitSet(adj_sid.flags(), 5)) {
								adj_sid.subtlv_length(5);
								unsigned char adj_label_array[3]{}; // loop to reduce
								adj_label_array[0] =
								    static_cast<unsigned char>((std::stoi(adj_label, 0, 10) >> 16) & 0xFF);
								adj_label_array[1] =
								    static_cast<unsigned char>((std::stoi(adj_label, 0, 10) >> 8) & 0xFF);
								adj_label_array[2] =
								    static_cast<unsigned char>((std::stoi(adj_label, 0, 10)) & 0xFF);
								adj_sid.sid(adj_label_array);
								length += 7;
								sub_length += 7;
								eth_length += 7;
								pdu_length += 7;
							} else {
								adj_sid.subtlv_length(6);
								unsigned char adj_label_array[4]{}; // loop to reduce
								adj_label_array[0] =
								    static_cast<unsigned char>((std::stoi(adj_label, 0, 10) >> 24) & 0xFF);
								adj_label_array[1] =
								    static_cast<unsigned char>((std::stoi(adj_label, 0, 10) >> 16) & 0xFF);
								adj_label_array[2] =
								    static_cast<unsigned char>((std::stoi(adj_label, 0, 10) >> 8) & 0xFF);
								adj_label_array[3] =
								    static_cast<unsigned char>((std::stoi(adj_label, 0, 10)) & 0xFF);
								adj_sid.offset(adj_label_array);
								length += 8;
								sub_length += 8;
								eth_length += 8;
								pdu_length += 8;
							}

							adj_sid_found = true;
							adj_sid_vec.push_back(adj_sid);
						}
					}

					if (mt222) {
						mt_ext_reach.subclv_length(sub_length);
						mt_ext_reach.tlv_length(length - 2);
						os_checksum << mt_ext_reach;
						os_tlvs << mt_ext_reach;
						if (sub_length) {
							// need to update to match tlv 22 below
							os_checksum << ip_interface_addr << neighbor_ip_addr;
							os_tlvs << ip_interface_addr << neighbor_ip_addr;

							if (ifindex_found) {
								os_checksum << local_remote_ifindex;
								os_tlvs << local_remote_ifindex;
							}
						}
					} else {
						ext_reach.subclv_length(sub_length);
						ext_reach.tlv_length(length - 2);
						os_checksum << ext_reach;
						os_tlvs << ext_reach;
						if (sub_length) {
							if (ip_interface_found) {
								os_checksum << ip_interface_addr;
								os_tlvs << ip_interface_addr;
							}
							if (neighbor_ip_found) {
								os_checksum << neighbor_ip_addr;
								os_tlvs << neighbor_ip_addr;
							}
							if (ifindex_found) {
								os_checksum << local_remote_ifindex;
								os_tlvs << local_remote_ifindex;
							}
							if (adj_sid_found) {
								for (auto i : adj_sid_vec) {
									os_checksum << i;
									os_tlvs << i;
								}
							}
						}
					}
					// TE
				}  
			}

			// SR 
		}
                

		/* Ext IP reachability tlv 135 (MT tlv 235) */
		for (const auto& item : data[i]["isis-tlv"][0].items()) {
			std::string key_str = std::string(item.key());
			if (key_str.find("ip-prefix-tlv") != std::string::npos) {   
				if (!data[i]["isis-tlv"][0][key_str][0]["address-prefix"][0]["data"].is_null()) {
					tlv_135 ext_ip_reach;
					tlv_235 mt_ext_ip_reach;
					bool mt235 = false;
					if (!data[i]["isis-tlv"][0][key_str][0]["isis-topology-id"][0]["data"].is_null()) {
						std::string topology_id_str =
						    std::string(data[i]["isis-tlv"][0][key_str][0]["isis-topology-id"][0]["data"]);
						if (topology_id_str.compare("IPV4 Unicast") == 0) {
							mt_ext_ip_reach.topology_id(0);
						}
						if (topology_id_str.compare("IPV6 Unicast") == 0) {
							mt_ext_ip_reach.topology_id(2);
						}
						if (topology_id_str.compare("IPV4 Multicast") == 0) {
							mt_ext_ip_reach.topology_id(3);
						}
						if (topology_id_str.compare("IPV6 Multicast") == 0) {
							mt_ext_ip_reach.topology_id(4);
						}

						mt235 = true;
					}
					unsigned int length = 2;
					if (mt235) {
						eth_length += 4;
						pdu_length += 4;
						length += 2;

					} else {
						eth_length += 2;
						pdu_length += 2;
					}
					boost::asio::streambuf tlv135_temp;
					std::ostream tlv135_stream(&tlv135_temp);
					std::vector<prefix_sid> ps_vector;
					for (const auto& subitem : data[i]["isis-tlv"][0][key_str].items()) {
						if (!data[i]["isis-tlv"][0][key_str][std::stoi(subitem.key())]["address-prefix"][0]["data"]
							 .is_null()) {
							/* handling new Junos tlv 135 json representaion, tlv 135,
							    not 235 yet */
							if (length > 210) {
								/* draining vector as well */
								for (const auto& i : ps_vector) {
									tlv135_stream << i;
								}
								std::string tlv135_intermediate_str(
								    boost::asio::buffers_begin(tlv135_temp.data()),
								    boost::asio::buffers_begin(tlv135_temp.data()) + tlv135_temp.size());
								tlv135_temp.consume(tlv135_intermediate_str.length());
								tlv_135 ext_ip_reach_intermediate;
								ext_ip_reach_intermediate.tlv_length(length - 2);
								os_checksum << ext_ip_reach_intermediate << tlv135_intermediate_str;
								os_tlvs << ext_ip_reach_intermediate << tlv135_intermediate_str;
								if (ps_vector.size()) {
									eth_length += 3;
									pdu_length += 3;
									length = 3;

								} else {
									eth_length += 2;
									pdu_length += 2;
									length = 2;
								}
								ps_vector.clear();
							}
							tlv135_ipreach ipreach;
							length += 9;
							eth_length += 9;
							pdu_length += 9;

							std::string ip_metric_str = std::string(
							    data[i]["isis-tlv"][0][key_str][std::stoi(subitem.key())]["metric"][0]["data"]);
							std::unique_ptr<unsigned char[]> ip_metric_array = metric_to_bytes(ip_metric_str);
							ipreach.metric(ip_metric_array.get());

							std::string ip_prefix = std::string(
							    data[i]["isis-tlv"][0][key_str][std::stoi(subitem.key())]["address-"
														      "prefix"][0]["data"]);
							std::unique_ptr<unsigned char[]> ip_prefix_array = prefix_to_bytes(ip_prefix);
							ipreach.ipv4_prefix(ip_prefix_array.get());

							unsigned char flags = prefix_length_to_bytes(ip_prefix);
                                                        /* save to aux db */
                                                        /*maskdb[std::string(reinterpret_cast<char*>(lsp_id_packed), 6)]
                                                             [std::string(reinterpret_cast<char*>(ip_prefix_array.get()), 4)] 
                                                              = int(flags);*/

							if (std::string(data[i]["isis-tlv"][0][key_str][std::stoi(subitem.key())]["prefix-"
																  "status"]
									    [0]["data"]) == "down") {
								flags |= 1 << 7;
							}
							/* adjusting length as per prefix length */
							unsigned int diff = 4 - ((unsigned int)(flags & 0x3F)) / 8;
							if (((unsigned int)(flags & 0x3F) % 8 != 0)) {
								diff--;
							}
							length -= diff;
							eth_length -= diff;
							pdu_length -= diff;

							ipreach.flags(flags);
                                                        auxdb[sys_id_temp].get()->SUBNETS_.push_back(ip_prefix);
							/* sr subtlv */
							// std::vector<prefix_sid> ps_vector;
							unsigned int sub_clv_length{};
							bool prefix_sid_found = false;
							/* loop over sub fields */
							for (const auto& subtlvitem :
							     data[i]["isis-tlv"][0][key_str][std::stoi(subitem.key())]["isis-prefix-subtlv"]
								 .items()) {
								if (!data[i]["isis-tlv"][0][key_str][std::stoi(subitem.key())]
									 ["isis-prefix-subtlv"][std::stoi(subtlvitem.key())]
									 ["isis-prefix-sid"][0]["isis-prefix-sid-flags"][0]["data"]
									     .is_null()) {
									prefix_sid ps;
									prefix_sid_found = true;
									std::string ps_flags = std::string(
									    data[i]["isis-tlv"][0][key_str][std::stoi(subitem.key())]
										["isis-prefix-subtlv"][std::stoi(subtlvitem.key())]
										["isis-prefix-sid"][0]["isis-prefix-sid-flags"][0]["data"]);
									ps_flags.erase(0, 2);
									std::string ps_flags_clean = ps_flags.substr(0, ps_flags.find("("));
									ps.flags(
									    static_cast<unsigned char>(std::stoi(ps_flags_clean, 0, 16)));
									if (!data[i]["isis-tlv"][0][key_str][std::stoi(subitem.key())]
										 ["isis-prefix-subtlv"][std::stoi(subtlvitem.key())]
										 ["isis-prefix-sid"][0]["isis-prefix-sid-algorithm"][0]
										 ["data"]
										     .is_null()) {
										std::string ps_algo = std::string(
										    data[i]["isis-tlv"][0][key_str]
											[std::stoi(subitem.key())]["isis-prefix-subtlv"]
											[std::stoi(subtlvitem.key())]["isis-prefix-sid"][0]
											["isis-prefix-sid-algorithm"][0]["data"]);
										if (ps_algo.find("Strict") != std::string::npos) {
											ps.algo(1);
										}
									}

									std::string ps_label = std::string(
									    data[i]["isis-tlv"][0][key_str][std::stoi(subitem.key())]
										["isis-prefix-subtlv"][std::stoi(subtlvitem.key())]
										["isis-prefix-sid"][0]["isis-prefix-sid-value"][0]["data"]);

									/* check V, L flags */
									if (isKthBitSet(ps.flags(), 2) && isKthBitSet(ps.flags(), 3)) {
										length += 7;
										eth_length += 7;
										pdu_length += 7;
										sub_clv_length += 7;
										ps.tlv_length(5);
										unsigned char ps_label_array[3]{}; // loop 
										ps_label_array[0] = static_cast<unsigned char>(
										    (std::stoi(ps_label, 0, 10) >> 16) & 0xFF);
										ps_label_array[1] = static_cast<unsigned char>(
										    (std::stoi(ps_label, 0, 10) >> 8) & 0xFF);
										ps_label_array[2] = static_cast<unsigned char>(
										    (std::stoi(ps_label, 0, 10)) & 0xFF);
										ps.label(ps_label_array);
									} else {
										length += 8;
										eth_length += 8;
										pdu_length += 8;
										sub_clv_length += 8;
										ps.tlv_length(6);
										unsigned char ps_label_array[4]{};
										ps_label_array[0] = static_cast<unsigned char>(
										    (std::stoi(ps_label, 0, 10) >> 24) & 0xFF);
										ps_label_array[1] = static_cast<unsigned char>(
										    (std::stoi(ps_label, 0, 10) >> 16) & 0xFF);
										ps_label_array[2] = static_cast<unsigned char>(
										    (std::stoi(ps_label, 0, 10) >> 8) & 0xFF);
										ps_label_array[3] = static_cast<unsigned char>(
										    (std::stoi(ps_label, 0, 10)) & 0xFF);
										ps.offset(ps_label_array);
									}
									ps_vector.push_back(ps);
								}
							}
							if (prefix_sid_found) {
								ipreach.sub_clv_length(static_cast<unsigned char>(sub_clv_length));
								ipreach.sub_clv_present();
								length++;
								eth_length++;
								pdu_length++;
							}
							tlv135_stream << ipreach;
							if (prefix_sid_found) {
								for (const auto& i : ps_vector) {
									tlv135_stream << i;
								}
							}
							ps_vector.clear();
						}
					}
					std::string tlv135_temp_str(boost::asio::buffers_begin(tlv135_temp.data()),
								    boost::asio::buffers_begin(tlv135_temp.data()) + tlv135_temp.size());

					if (mt235) {
						mt_ext_ip_reach.tlv_length(length - 2);
						os_checksum << mt_ext_ip_reach << tlv135_temp_str;
						os_tlvs << mt_ext_ip_reach << tlv135_temp_str;

					} else {
						ext_ip_reach.tlv_length(length - 2);
						os_checksum << ext_ip_reach << tlv135_temp_str;
						os_tlvs << ext_ip_reach << tlv135_temp_str;
					}
				}
			}
		}

		/* router capability tlv 242 */
		if (!data[i]["isis-tlv"][0]["rtr-capability-tlv"][0]["router-id"][0]["data"].is_null()) {
			tlv_242 rtr_capability;
			eth_length += 7;
			pdu_length += 7;

			std::string rtr_id_str = std::string(data[i]["isis-tlv"][0]["rtr-capability-tlv"][0]["router-id"][0]["data"]);
			std::unique_ptr<unsigned char[]> rtr_id = prefix_to_bytes(rtr_id_str);
			rtr_capability.router_id(rtr_id.get());
			std::string rtr_flags_str =
			    std::string(data[i]["isis-tlv"][0]["rtr-capability-tlv"][0]["rtr-cap-flags"][0]["data"]);
			rtr_flags_str.erase(0, 2);
			rtr_capability.flags(static_cast<unsigned char>(std::stoi(rtr_flags_str, 0, 16)));
			/* sr subtlv */
			bool sr_found = false;
			bool msd_found = false;
			bool algo_found = false;
			subtlv242_2 router_capability;
			subtlv242_23 msd;
			subtlv242_19 algo;
			std::vector<unsigned char> algos;

			if (!data[i]["isis-tlv"][0]["rtr-capability-tlv"][0]["spring-capability-sub-tlv"][0]["spring-capability-flags"][0]
				 ["data"]
				     .is_null()) {
				sr_found = true;
				std::string s_flags =
				    std::string(data[i]["isis-tlv"][0]["rtr-capability-tlv"][0]["spring-capability-sub-tlv"][0]
						    ["spring-capability-flags"][0]["data"]);
				s_flags.erase(0, 2);
				s_flags = s_flags.substr(0, s_flags.find("("));
				router_capability.flags(static_cast<unsigned char>(std::stoi(s_flags, 0, 16)));
				std::string s_range =
				    std::string(data[i]["isis-tlv"][0]["rtr-capability-tlv"][0]["spring-capability-sub-tlv"][0]
						    ["spring-capability-range"][0]["data"]);
				unsigned char s_range_array[3]{};  // loop 
				s_range_array[0] = static_cast<unsigned char>((std::stoi(s_range, 0, 10) >> 16) & 0xFF);
				s_range_array[1] = static_cast<unsigned char>((std::stoi(s_range, 0, 10) >> 8) & 0xFF);
				s_range_array[2] = static_cast<unsigned char>((std::stoi(s_range, 0, 10)) & 0xFF);
				router_capability.range(s_range_array);

				std::string s_label =
				    std::string(data[i]["isis-tlv"][0]["rtr-capability-tlv"][0]["spring-capability-sub-tlv"][0]
						    ["spring-capability-sid-label"][0]["data"]);

				unsigned char s_label_array[5]{};
				s_label_array[0] = 0x01;
				s_label_array[1] = 0x03; 
				s_label_array[2] = static_cast<unsigned char>((std::stoi(s_label, 0, 10) >> 16) & 0xFF);
				s_label_array[3] = static_cast<unsigned char>((std::stoi(s_label, 0, 10) >> 8) & 0xFF);
				s_label_array[4] = static_cast<unsigned char>((std::stoi(s_label, 0, 10)) & 0xFF);
				router_capability.sid_label(s_label_array);
				eth_length += 11;
				pdu_length += 11;
				rtr_capability.tlv_length(
				    static_cast<unsigned char>(static_cast<unsigned int>(rtr_capability.get_length()) + 11));
			}

			if (!data[i]["isis-tlv"][0]["rtr-capability-tlv"][0]["node-msd-adv-sub-tlv"][0]["msd-type"][0]["data"].is_null()) {
				/* no support for subtlv msd */
				msd_found = true;
				std::string msd_type_str = std::string(
				    data[i]["isis-tlv"][0]["rtr-capability-tlv"][0]["node-msd-adv-sub-tlv"][0]["msd-type"][0]["data"]);
				std::string msd_length_str = std::string(
				    data[i]["isis-tlv"][0]["rtr-capability-tlv"][0]["node-msd-adv-sub-tlv"][0]["msd-length"][0]["data"]);
				msd.msd_type(static_cast<unsigned char>(std::stoi(msd_type_str)));
				msd.msd_value(static_cast<unsigned char>(std::stoi(msd_length_str)));
				eth_length += 4;
				pdu_length += 4;
				rtr_capability.tlv_length(
				    static_cast<unsigned char>(static_cast<unsigned int>(rtr_capability.get_length()) + 4));
			}

			if (!data[i]["isis-tlv"][0]["rtr-capability-tlv"][0]["spring-algorithm-sub-tlv"][0]["spring-algorithm-type"][0]
				 ["data"]
				     .is_null()) {
				algo_found = true;
				for (const auto& algo_item :
				     data[i]["isis-tlv"][0]["rtr-capability-tlv"][0]["spring-algorithm-sub-tlv"][0]["spring-algorithm-type"]
					 .items()) {
					std::string algo_str = data[i]["isis-tlv"][0]["rtr-capability-tlv"][0]["spring-algorithm-sub-tlv"]
								   [0]["spring-algorithm-type"][std::stoi(algo_item.key())]["data"];
					unsigned char onealgo = static_cast<unsigned char>(std::stoi(std::string(algo_str), 0, 10));
					algos.push_back(onealgo);
				}
				algo.tlv_length(static_cast<unsigned char>(algos.size()));
				eth_length += 2 + static_cast<unsigned int>(algos.size());
				pdu_length += 2 + static_cast<unsigned int>(algos.size());
				rtr_capability.tlv_length(static_cast<unsigned char>(
				    static_cast<unsigned int>(rtr_capability.get_length()) + 2 + static_cast<unsigned int>(algos.size())));
			}

			os_checksum << rtr_capability;
			os_tlvs << rtr_capability;
			if (sr_found) {
				os_checksum << router_capability;
				os_tlvs << router_capability;
			}
			if (msd_found) {
				os_checksum << msd;
				os_tlvs << msd;
			}
			if (algo_found) {
				os_checksum << algo;
				os_tlvs << algo;
				for (const auto& algo_item : algos) {
					subtlv242_19_algo temp;
					temp.algo(algo_item);
					os_checksum << temp;
					os_tlvs << temp;
				}
			}
		}
		if (!data[i]["isis-prefix"][0]["isis-topology-id"][0]["data"].is_null()) {
                        #ifdef DEBUG
			std::cout << "Multi-topology:" << std::endl;
                        #endif
			std::vector<unsigned int> status(4, 0);
			for (const auto& subitem : data[i]["isis-prefix"].items()) {
				if (!data[i]["isis-prefix"][std::stoi(subitem.key())]["isis-topology-id"][0]["data"].is_null()) {
					std::string topology_string =
					    data[i]["isis-prefix"][std::stoi(subitem.key())]["isis-topology-id"][0]["data"];
					if (!status[0] && topology_string.compare("IPV4 Unicast") == 0) {
						status[0] = 1;
					}
					if (!status[1] && topology_string.compare("IPV6 Unicast") == 0) {
						status[1] = 1;
					}
					if (!status[2] && topology_string.compare("IPV4 Multicast") == 0) {
						status[2] = 1;
					}
					if (!status[3] && topology_string.compare("IPV6 Multicast") == 0) {
						status[3] = 1;
					}
				}
			}
			unsigned int mt_length{};
			boost::asio::streambuf mt_temp;
			std::ostream mt_stream(&mt_temp);
			if (status[0]) {
                                #ifdef DEBUG
				std::cout << "IPv4 unicast" << std::endl;
                                #endif
				mt_length++;
				tlv_229_topology ipv4_unicast;
				ipv4_unicast.topology(0);
				mt_stream << ipv4_unicast;
			};
			if (status[1]) {
                                #ifdef DEBUG
				std::cout << "IPv6 unicast" << std::endl;
                                #endif
				mt_length++;
				tlv_229_topology ipv6_unicast;
				ipv6_unicast.topology(2);
				mt_stream << ipv6_unicast;
			};
			if (status[2]) {
                                #ifdef DEBUG
				std::cout << "IPv4 multicast" << std::endl;
                                #endif
				mt_length++;
				tlv_229_topology ipv4_multicast;
				ipv4_multicast.topology(3);
				mt_stream << ipv4_multicast;
			};
			if (status[3]) {
                                #ifdef DEBUG
				std::cout << "IPv6 multicast" << std::endl;
                                #endif
				mt_length++;
				tlv_229_topology ipv6_multicast;
				ipv6_multicast.topology(4);
				mt_stream << ipv6_multicast;
			};
			std::string mt_str(boost::asio::buffers_begin(mt_temp.data()),
					   boost::asio::buffers_begin(mt_temp.data()) + mt_temp.size());
			tlv_229 multitopology;
			multitopology.tlv_length(2 * mt_length);
			os_checksum << multitopology << mt_str;
			os_tlvs << multitopology << mt_str;
			// our_mt_str = mt_str;
			// our_mt_length = mt_length;
			eth_length += 2 * mt_length + 2;  
			pdu_length += 2 * mt_length + 2;
		}
		// more TLVs go here
		eth.length(eth_length);
		lsp_header.pdu_length(htons(pdu_length));
		/* calculating checksum */ 
		std::string checksum_str(boost::asio::buffers_begin(checksum_pdu.data()),
					 boost::asio::buffers_begin(checksum_pdu.data()) + checksum_pdu.size());
		std::unique_ptr<unsigned char[]> checksum_temp_ptr(new unsigned char[checksum_str.size()]{});
		unsigned char* checksum_temp = checksum_temp_ptr.get();

		std::memcpy(checksum_temp, checksum_str.c_str(), checksum_str.size());
		unsigned short checksum = htons(fletcher_checksum(checksum_temp + 12, checksum_str.size() - 12, 12));
		lsp_header.checksum(htons(checksum));
               
		/* constructing final packet lsp part */
		std::string tlvs_str(boost::asio::buffers_begin(tlvs.data()), boost::asio::buffers_begin(tlvs.data()) + tlvs.size());
		os << eth << isis << lsp_header << tlvs_str;
		std::string packet_str(boost::asio::buffers_begin(packet.data()),
				       boost::asio::buffers_begin(packet.data()) + packet.size());



		/* saving packet to db */
		lsdb.insert(std::pair<std::string, std::string>(keys[i], packet_str));
	}

        // parse json-raw, lookup in auxdb, attach eth header, fill length          
        if ( file_json_raw.length() ) {
               std::ifstream f2(file_json_raw);
               json raw2 = json::parse(f2);

               json data2 = raw2["isis-database-information"][0]["isis-database"][1]["isis-database-entry"];
               for (const auto& item : data2) {
                       std::string hostname =  item["isis-packet"][0]["lsp-id"][0]["data"];
                       for (int i=0; i<6; i++) hostname.pop_back();
                       std::string lspid;
                       for (const auto& k: auxdb ) { 
                                if ( k.second.get()->HOSTNAME_ == hostname ) {
                                              lspid = k.first;
                                              break;
                                }
                       }                                       

                       // eth header and convert body 
                       std::string payload = item["isis-packet"][0]["isis-packet-base64"][0]["data"];
                       std::vector<unsigned char> payload_decoded = *std::move(base64pp::decode(payload));
                       std::string lsp_body(payload_decoded.begin(),payload_decoded.end());  
                       // size of body and eth header 
                       eth_header eth;                                                                                                        
                       eth.length(3 + lsp_body.length());
                       boost::asio::streambuf packet_raw;
                       std::ostream os_raw(&packet_raw);
                       os_raw << eth << lsp_body;
                       std::string packet_raw_str(boost::asio::buffers_begin(packet_raw.data()),
                                       boost::asio::buffers_begin(packet_raw.data()) + packet_raw.size());       

                       lsdb_raw.insert(std::pair<std::string, std::string>(lspid, packet_raw_str));  
                       
               }
                
        


        }

        std::cout << "done" << std::endl;
	f.close();
}

