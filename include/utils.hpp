#pragma once
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if.h>

#include <boost/algorithm/string.hpp>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <istream>
#include <streambuf>
#include <regex>
#include <algorithm>

std::ostream& render_printable_chars(std::ostream& os, const char* buffer, size_t bufsize) {
	os << " | ";
	for (size_t i = 0; i < bufsize; ++i) {
		if (std::isprint(buffer[i])) {
			os << buffer[i];
		} else {
			os << ".";
		}
	}
	return os;
}

std::ostream& hex_dump(std::ostream& os, const uint8_t* buffer, size_t bufsize, bool showPrintableChars = true) {
	auto oldFormat = os.flags();
	auto oldFillChar = os.fill();

	os << std::hex;
	os.fill('0');
	bool printBlank = false;
	size_t i = 0;
	for (; i < bufsize; ++i) {
		if (i % 8 == 0) {
			if (i != 0 && showPrintableChars) {
				render_printable_chars(os, reinterpret_cast<const char*>(&buffer[i] - 8), 8);
			}
			os << std::endl;
			printBlank = false;
		}
		if (printBlank) {
			os << ' ';
		}
		os << std::setw(2) << std::right << unsigned(buffer[i]);
		if (!printBlank) {
			printBlank = true;
		}
	}
	if (i % 8 != 0 && showPrintableChars) {
		for (size_t j = 0; j < 8 - (i % 8); ++j) {
			os << "   ";
		}
		render_printable_chars(os, reinterpret_cast<const char*>(&buffer[i] - (i % 8)), (i % 8));
	}

	os << std::endl;

	os.fill(oldFillChar);
	os.flags(oldFormat);

	return os;
}

std::ostream& hex_dump(std::ostream& os, const std::string& buffer, bool showPrintableChars = true) {
	return hex_dump(os, reinterpret_cast<const uint8_t*>(buffer.data()), buffer.length(), showPrintableChars);
}

#define FLETCHER_CHECKSUM_VALIDATE 0xffff
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

/* Fletcher Checksum -- Refer to RFC1008. */
#define MODX 4102U /* 5802 should be fine */

/* To be consistent, offset is 0-based index, rather than the 1-based
   index required in the specification ISO 8473, Annex C.1 */
/* calling with offset == FLETCHER_CHECKSUM_VALIDATE will validate the checksum
   without modifying the buffer; a valid checksum returns 0 */
uint16_t fletcher_checksum(uint8_t* buffer, const size_t len, const uint16_t offset) {
	uint8_t* p;
	int x, y, c0, c1;
	uint16_t checksum = 0;
	uint16_t* csum;
	size_t partial_len, i, left = len;

	if (offset != FLETCHER_CHECKSUM_VALIDATE)
	/* Zero the csum in the packet. */
	{
		// assert(offset
		//       < (len - 1)); /* account for two bytes of checksum */
		if (offset >= (len - 1)) {
			std::cout << "Warning, offset equal or more than len-1" << std::endl;
		}
		csum = (uint16_t*)(buffer + offset);
		*(csum) = 0;
	}

	p = buffer;
	c0 = 0;
	c1 = 0;

	while (left != 0) {
		partial_len = MIN(left, MODX);

		for (i = 0; i < partial_len; i++) {
			c0 = c0 + *(p++);
			c1 += c0;
		}

		c0 = c0 % 255;
		c1 = c1 % 255;

		left -= partial_len;
	}

	/* The cast is important, to ensure the mod is taken as a signed value.
	 */
	x = (int)((len - offset - 1) * c0 - c1) % 255;

	if (x <= 0) x += 255;
	y = 510 - c0 - x;
	if (y > 255) y -= 255;

	if (offset == FLETCHER_CHECKSUM_VALIDATE) {
		checksum = (c1 << 8) + c0;
	} else {
		/*
		 * Now we write this to the packet.
		 * We could skip this step too, since the checksum returned
		 * would
		 * be stored into the checksum field by the caller.
		 */
		buffer[offset] = x;
		buffer[offset + 1] = y;

		/* Take care of the endian issue */
		checksum = htons((x << 8) | (y & 0xFF));
	}

	return checksum;
}

class IPv6Address {
    public:
	IPv6Address();

	bool fromString(const char* addrstr);
	unsigned char* getAddr() { return &_address[0]; }

	void print();

    private:
	unsigned char _address[16];
} __attribute__((__packed__));

IPv6Address::IPv6Address() { memset(_address, 0, sizeof(_address)); }

#define MAX_IPV6_ADDRESS_STR_LEN 39

static int8_t asciiToHex(char c) {
	c |= 0x20;

	if (c >= '0' && c <= '9') {
		return c - '0';
	} else if (c >= 'a' && c <= 'f') {
		return (c - 'a') + 10;
	} else {
		return -1;
	}
}

bool IPv6Address::fromString(const char* addrstr) {
	uint16_t accumulator = 0;
	uint8_t colon_count = 0;
	uint8_t pos = 0;

	memset(_address, 0, sizeof(_address));

	// Step 1: look for position of ::, and count colons after it
	for (uint8_t i = 1; i <= MAX_IPV6_ADDRESS_STR_LEN; i++) {
		if (addrstr[i] == ':') {
			if (addrstr[i - 1] == ':') {
				// Double colon!
				colon_count = 14;
			} else if (colon_count) {
				// Count backwards the number of colons after
				// the ::
				colon_count -= 2;
			}
		} else if (addrstr[i] == '\0') {
			break;
		}
	}

	// Step 2: convert from ascii to binary
	for (uint8_t i = 0; i <= MAX_IPV6_ADDRESS_STR_LEN && pos < 16; i++) {
		if (addrstr[i] == ':' || addrstr[i] == '\0') {
			_address[pos] = accumulator >> 8;
			_address[pos + 1] = accumulator;
			accumulator = 0;

			if (colon_count && i && addrstr[i - 1] == ':') {
				pos = colon_count;
			} else {
				pos += 2;
			}
		} else {
			int8_t val = asciiToHex(addrstr[i]);
			if (val == -1) {
				// Not hex or colon: fail
				return 0;
			} else {
				accumulator <<= 4;
				accumulator |= val;
			}
		}

		if (addrstr[i] == '\0') break;
	}

	// Success
	return 1;
}

std::unique_ptr<unsigned char[]> num_to_array(std::string& num_str, unsigned int size) {
	unsigned int num{};
	if (!num_str.find("0x")) {
		num_str.erase(0, 2);
		num = std::stol(num_str, 0, 16);
	} else {
		num = std::stol(num_str);
	}

	std::unique_ptr<unsigned char[]> num_ptr(new unsigned char[size]{});
	unsigned char* num_array = num_ptr.get();
	for (unsigned int i = 0; i < size; i++) {
		num_array[i] = (num >> (size - i - 1) * 8) & 0xFF;
	}
	return num_ptr;
}

std::unique_ptr<unsigned char[]> area_to_bytes(std::string& area_str) {
	std::string area_part1{}, area_part2{};
	std::unique_ptr<unsigned char[]> area_ptr(new unsigned char[(area_str.length() / 2)]{});
	for (size_t i = 0, j = 0; i < area_str.length() && j < area_str.length(); i += 2, j++) {
		area_part1 = area_str[i];
		area_part2 = area_str[i + 1];
		(area_ptr.get())[j] = static_cast<unsigned char>(16 * std::stoi(area_part1, 0, 16) + std::stoi(area_part2, 0, 16));
	}

	return area_ptr;
}



std::unique_ptr<unsigned char[]> prefix_to_bytes(std::string prefix) {
	std::string prefix_delimiter = "/", delimiter = ".";
	size_t pos = 0;
	pos = prefix.find(prefix_delimiter);
	std::string ip = prefix.substr(0, pos);
	std::string length = prefix.substr(pos + 1);

	std::string part_1{}, part_2{}, part_3{}, part_4{};

	pos = ip.find(delimiter);
	part_1 = ip.substr(0, pos);
	ip.erase(0, pos + 1);
	pos = ip.find(delimiter);
	part_2 = ip.substr(0, pos);
	ip.erase(0, pos + 1);
	pos = ip.find(delimiter);
	part_3 = ip.substr(0, pos);
	ip.erase(0, pos + 1);
	part_4 = ip;
	std::unique_ptr<unsigned char[]> ip_ptr(new unsigned char[4]{});
	unsigned char* ip_array = ip_ptr.get();
	ip_array[0] = static_cast<unsigned char>(std::stoi(part_1, 0, 10));
	ip_array[1] = static_cast<unsigned char>(std::stoi(part_2, 0, 10));
	ip_array[2] = static_cast<unsigned char>(std::stoi(part_3, 0, 10));
	ip_array[3] = static_cast<unsigned char>(std::stoi(part_4, 0, 10));
	return ip_ptr;
}

unsigned char prefix_length_to_bytes(std::string prefix) {
	std::string prefix_delimiter = "/";
	size_t pos = 0;
	pos = prefix.find(prefix_delimiter);
	std::string length = prefix.substr(pos + 1);
	return static_cast<unsigned char>(std::stoi(length));
}

std::unique_ptr<unsigned char[]> metric_to_bytes(std::string metric) {
	unsigned int ip_metric = std::stoi(metric);
	std::unique_ptr<unsigned char[]> ip_metric_ptr(new unsigned char[4]{});
	unsigned char* ip_metric_array = ip_metric_ptr.get();
	ip_metric_array[3] = static_cast<unsigned char>((ip_metric >> 0) & 0xFF);
	ip_metric_array[2] = static_cast<unsigned char>((ip_metric >> 8) & 0xFF);
	ip_metric_array[1] = static_cast<unsigned char>((ip_metric >> 16) & 0xFF);
	ip_metric_array[0] = static_cast<unsigned char>((ip_metric >> 24) & 0xFF);
	return ip_metric_ptr;
}

bool isKthBitSet(unsigned char n, int k) {
	if (n & (1 << k))
		return true;
	else
		return false;
}

void incrSequenceNum(std::unordered_map<std::string, std::string>& LSDB, const std::string& key, const std::string& value) {
	std::string new_value = value;
	std::string seq_num_str = value.substr(37, 4);

	unsigned int seq_num = static_cast<unsigned int>(static_cast<unsigned char>(seq_num_str[0])) << 24 |
			       static_cast<unsigned int>(static_cast<unsigned char>(seq_num_str[1])) << 16 |
			       static_cast<unsigned int>(static_cast<unsigned char>(seq_num_str[2])) << 8 |
			       static_cast<unsigned int>(static_cast<unsigned char>(seq_num_str[3]));
	seq_num++;
	new_value[40] = seq_num & 0x000000ff;
	new_value[39] = (seq_num & 0x0000ff00) >> 8;
	new_value[38] = (seq_num & 0x00ff0000) >> 16;
	new_value[37] = (seq_num & 0xff000000) >> 24;
	std::unique_ptr<unsigned char[]> checksum_temp_ptr(new unsigned char[new_value.size() - 17]{});
	unsigned char* checksum_temp = checksum_temp_ptr.get();
	new_value[41] = 0;
	new_value[42] = 0;
	std::memcpy(checksum_temp, new_value.c_str() + 17, new_value.size() - 17);

	unsigned short checksum = htons(fletcher_checksum(checksum_temp + 12, new_value.size() - 29, 12));
	new_value[41] = static_cast<unsigned char>(checksum >> 8);
	new_value[42] = static_cast<unsigned char>(checksum & 0xFF);
	LSDB[key] = new_value;

	return;
}


void interface_up(const char* ifname) { 
      int sockfd;
      struct ifreq ifr;

      sockfd = socket(AF_INET, SOCK_DGRAM, 0);

      if (sockfd < 0)
      return;

      memset(&ifr, 0, sizeof ifr);
      strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
      ifr.ifr_flags |= IFF_UP;
      ioctl(sockfd, SIOCSIFFLAGS, &ifr);
} 








