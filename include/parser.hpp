#pragma once
#include <stdint.h>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <unordered_set>
#include <vector>
#include <algorithm>

#include "base64pp.h"
#include "boost/algorithm/hex.hpp"
#include "isis.hpp"
#include "json.hpp"
#include "utils.hpp"

using json = nlohmann::json;

/*
 *  lsdb stores raw data taken from base64 offload from a router;
 *  aux db, stores graph of connectivity and addional info per node, readable format, key is sys id length 14 separated by "-".
 */

struct Router {
	std::map<std::string, std::pair<std::string, std::string>> NEIGHBORS_;
	std::vector<std::string> SUBNETS_;
	std::string AREA_{"_EMPTY_"};
	std::string HOSTNAME_;
};

typedef std::unordered_map<std::string, std::unique_ptr<struct Router>> auxdb;

void parse(std::unordered_map<std::string, std::string>& lsdb, auxdb& auxdb, const std::string& file_json,
	   const std::string& file_json_raw, const std::string& file_json_hostname) {
	std::cout << "Parsing JSON files..." << std::endl;

       /* build hostname mapping to sys-id */
       std::unordered_map<std::string,std::string> hostnames;
       std::ifstream h(file_json_hostname);
       json host = json::parse(h);
       json hostname_data = host["isis-hostname-information"][0]["isis-hostname"];

       for (const auto& item : hostname_data) { 
            hostnames.emplace(std::string(item["system-name"][0]["data"]),std::string(item["system-id"][0]["data"]));
            #ifdef DEBUG
            std::cout << std::string(item["system-name"][0]["data"]) << " " << std::string(item["system-id"][0]["data"]) << std::endl;
            #endif
        }
        h.close();

	/* collect info to build auxdb */
	std::ifstream f(file_json);
	json raw = json::parse(f);
	std::vector<std::string> keys;

	json data = raw["isis-database-information"][0]["isis-database"][1]["isis-database-entry"];
	for (const auto& item : data) {
		if (item.find("lsp-id") != item.end()) {
			for (const auto& item2 : item["lsp-id"]) {
                                if ( hostnames.count(std::string(item2["data"])) ) { 
				       keys.push_back(hostnames[std::string(item2["data"])]);
                                } else {
                                       keys.push_back(std::string(item2["data"]));
                                }
			}
		}
	}
        #ifdef DEBUG
	std::cout << "Found LSPs count: " << keys.size() << std::endl;
        #endif
	if (!keys.size()) {
		throw std::runtime_error(std::string("no LSPs found in json provided"));
	}

	for (int i = 0; i < int(keys.size()); ++i) {
		std::string lsp_id = std::string(data[i]["lsp-id"][0]["data"]);
                #ifdef DEBUG
		std::cout << i << " LSP-ID " << lsp_id << std::endl;
                #endif

		std::unique_ptr<struct Router> temp(new struct Router);
                for (int i=0; i<6; i++ ) lsp_id.pop_back();
                std::string resolved_lsp_id = hostnames[lsp_id];
		auxdb.insert(std::make_pair(resolved_lsp_id, std::move(temp)));

		/* Hostname tlv */
		if (!data[i]["isis-tlv"][0]["hostname-tlv"][0]["hostname"][0]["data"].is_null()) {
			std::string hostname_str = std::string(data[i]["isis-tlv"][0]["hostname-tlv"][0]["hostname"][0]["data"]);
			auxdb[resolved_lsp_id].get()->HOSTNAME_ = hostname_str;
                        #ifdef DEBUG
			std::cout << "hostname: " << hostname_str << std::endl;
                        #endif
		}

		/* Area address TLV 1 */
		if (!data[i]["isis-tlv"][0]["area-address-tlv"][0]["address"][0]["data"].is_null()) {
			std::string area_str = data[i]["isis-tlv"][0]["area-address-tlv"][0]["address"][0]["data"];
			auxdb[resolved_lsp_id].get()->AREA_ = area_str;
		}

		/* ISIS reachability TLV 22 */
		for (const auto& item : data[i]["isis-tlv"][0].items()) {
			std::string key_str = std::string(item.key());
			if (key_str.find("reachability-tlv") != std::string::npos && key_str.find("ipv6") == std::string::npos) {
				for (const auto& subindex : data[i]["isis-tlv"][0][key_str].items()) {
					/* subTLVs */
					int sub_key_str = std::stoi(subindex.key());
					for (const auto& subitem :
					     data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-reachability-subtlv"].items()) {
						std::string neighbor_map_str =
						    std::string(data[i]["isis-tlv"][0][key_str][sub_key_str]["address-prefix"][0]["data"]);

						if (!data[i]["isis-tlv"][0][key_str][sub_key_str]["isis-reachability-"
												  "subtlv"][std::stoi(subitem.key())]
							 ["address"][0]["data"]
							     .is_null()) {
							std::string ip_interface_addr_str =
							    data[i]["isis-tlv"][0][key_str][sub_key_str]
								["isis-"
								 "reachability-"
								 "subtlv"][std::stoi(subitem.key())]["address"][0]["data"];
							auxdb[resolved_lsp_id].get()->NEIGHBORS_[neighbor_map_str.substr(0, 14)].first =
							    ip_interface_addr_str;
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
							auxdb[resolved_lsp_id].get()->NEIGHBORS_[neighbor_map_str.substr(0, 14)].second =
							    neighbor_ip_addr_str;
						}
					}
				}
			}
		}

		/* Ext IP reachability TLV 135 */
		for (const auto& item : data[i]["isis-tlv"][0].items()) {
			std::string key_str = std::string(item.key());
			if (key_str.find("ip-prefix-tlv") != std::string::npos) {
				if (!data[i]["isis-tlv"][0][key_str][0]["address-prefix"][0]["data"].is_null()) {
					for (const auto& subitem : data[i]["isis-tlv"][0][key_str].items()) {
						if (!data[i]["isis-tlv"][0][key_str][std::stoi(subitem.key())]["address-prefix"][0]["data"]
							 .is_null()) {
							std::string ip_prefix = std::string(
							    data[i]["isis-tlv"][0][key_str][std::stoi(subitem.key())]["address-"
														      "prefix"][0]["data"]);
							auxdb[resolved_lsp_id].get()->SUBNETS_.push_back(ip_prefix);
						}
					}
				}
			}
		}
	}
	f.close();

	/* build actual lsdb by getting base64 data */
	std::ifstream f2(file_json_raw);
	json raw2 = json::parse(f2);

	json data2 = raw2["isis-database-information"][0]["isis-database"][1]["isis-database-entry"];
	for (const auto& item : data2) {
		std::string hostname = item["isis-packet"][0]["lsp-id"][0]["data"];

		/* good to add check if LSP is not in sync between lsdb and aux -> action ? */
                std::string lspid, suffix;
		for (int i = 0; i < 6; i++) {
                             suffix+=hostname.back(); 
                             hostname.pop_back();
		}
                std::reverse(suffix.begin(),suffix.end());                             
		for (const auto& k : auxdb) {
			if (k.second.get()->HOSTNAME_ == hostname) {
				lspid = k.first + suffix;
				break;
			}
		}

		/* eth header and convert body to bytes */
		std::string payload = item["isis-packet"][0]["isis-packet-base64"][0]["data"];
		std::vector<unsigned char> payload_decoded = *std::move(base64pp::decode(payload));
		std::string lsp_body(payload_decoded.begin(), payload_decoded.end());
		/* size of the body and eth header */
		eth_header eth;
		eth.length(3 + lsp_body.length());

                /* fill data to form PSNP, CSNP */


		boost::asio::streambuf packet_raw;
		std::ostream os_raw(&packet_raw);
		os_raw << eth << lsp_body;
		std::string packet_raw_str(boost::asio::buffers_begin(packet_raw.data()),
					   boost::asio::buffers_begin(packet_raw.data()) + packet_raw.size());

		lsdb.insert(std::pair<std::string, std::string>(lspid, packet_raw_str));
	}
	f2.close();

	std::cout << "done" << std::endl;
}

