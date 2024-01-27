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
#include <ctime>
#include <iomanip>
#include <iostream>
#include <istream>
#include <streambuf>
#include <regex>
#include <algorithm>
#include <span>

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


std::unique_ptr<unsigned char[]> area_to_bytes(const std::string& area_str) {
	std::string area_part1{}, area_part2{};
	std::unique_ptr<unsigned char[]> area_ptr(new unsigned char[(area_str.length() / 2)]{});
	for (size_t i = 0, j = 0; i < area_str.length() && j < area_str.length(); i += 2, j++) {
		area_part1 = area_str[i];
		area_part2 = area_str[i + 1];
		(area_ptr.get())[j] = static_cast<unsigned char>(16 * std::stoi(area_part1, 0, 16) + std::stoi(area_part2, 0, 16));
	}

	return area_ptr;
}


/* not used in ISIS , but better to accept std::string there... */

std::unique_ptr<unsigned char[]> ip_to_bytes(std::string& ip_str) {       
        std::unique_ptr<unsigned char[]> ip_ptr(new unsigned char[4]{});
        unsigned char* ip_array = ip_ptr.get();
        std::string ip_delimiter = ".";
        size_t ip_pos{};
        for ( int i=0; i<4; i++) {
               ip_pos = ip_str.find(ip_delimiter);
               ip_array[i] = static_cast<unsigned char>(std::stoi(ip_str.substr(0, ip_pos), 0, 10));
               ip_str.erase(0, ip_pos + ip_delimiter.length());
         }
         return ip_ptr;

}



void inc_sequence_num(std::unordered_map<std::string, std::string>& LSDB, const std::string& key, const std::string& value, int inc) {
	std::string new_value = value;
	std::string seq_num_str = value.substr(37, 4);

	unsigned int seq_num = static_cast<unsigned int>(static_cast<unsigned char>(seq_num_str[0])) << 24 |
			       static_cast<unsigned int>(static_cast<unsigned char>(seq_num_str[1])) << 16 |
			       static_cast<unsigned int>(static_cast<unsigned char>(seq_num_str[2])) << 8 |
			       static_cast<unsigned int>(static_cast<unsigned char>(seq_num_str[3]));
	seq_num+=inc;
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

std::string time_stamp(){
    std::ostringstream strStream;
    std::time_t t = std::time(nullptr);
    strStream<< "[" << std::put_time(std::localtime(&t), "%F %T %Z") << "] ";
    return strStream.str();
} 

