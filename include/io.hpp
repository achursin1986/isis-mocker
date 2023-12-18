#pragma once
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>

#include <boost/asio.hpp>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include "isis.hpp"
#include "utils.hpp"

template <typename Protocol>
class ll_endpoint {
    private:
	sockaddr_ll sockaddr;

    public:
	typedef Protocol protocol_type;
	typedef boost::asio::detail::socket_addr_type data_type;

	ll_endpoint<Protocol>(char* ifname) {
		sockaddr.sll_family = PF_PACKET;
		sockaddr.sll_protocol = htons(ETH_P_ALL);
		sockaddr.sll_ifindex = if_nametoindex(ifname);
	}

	ll_endpoint() {
		sockaddr.sll_family = PF_PACKET;
		sockaddr.sll_protocol = htons(ETH_P_ALL);
		sockaddr.sll_ifindex = if_nametoindex("");
	}

	ll_endpoint<Protocol>& operator=(const ll_endpoint& other) {
		sockaddr = other.sockaddr;
		return *this;
	}

	protocol_type protocol() const { return protocol_type(); }

	data_type* data() { return (struct sockaddr*)&sockaddr; }

	const data_type* data() const { return (struct sockaddr*)&sockaddr; }

	std::size_t size() const { return sizeof(sockaddr); }

	void resize(std::size_t size) {
		/* make compiler happy */
		(void)size;
	}

	std::size_t capacity() const { return sizeof(sockaddr); }

	friend bool operator==(const ll_endpoint<Protocol>& e1,
			       const ll_endpoint<Protocol>& e2) {
		return (e1.sockaddr.sll_addr == e2.sockaddr.sll_addr);
	}

	friend bool operator!=(const ll_endpoint<Protocol>& e1,
			       const ll_endpoint<Protocol>& e2) {
		return !(e1.sockaddr.sll_addr == e2.sockaddr.sll_addr);
	}

	friend bool operator<(const ll_endpoint<Protocol>& e1,
			      const ll_endpoint<Protocol>& e2) {
		return e1.sockaddr.sll_addr < e2.sockaddr.sll_addr;
	}

	friend bool operator>(const ll_endpoint<Protocol>& e1,
			      const ll_endpoint<Protocol>& e2) {
		return e2.sockaddr.sll_addr < e1.sockaddr.sll_addr;
	}

	friend bool operator<=(const ll_endpoint<Protocol>& e1,
			       const ll_endpoint<Protocol>& e2) {
		return !(e2 < e1);
	}

	friend bool operator>=(const ll_endpoint<Protocol>& e1,
			       const ll_endpoint<Protocol>& e2) {
		return !(e1 < e2);
	}
};

class ll_protocol {
    public:
	typedef boost::asio::basic_raw_socket<ll_protocol> socket;
	typedef ll_endpoint<ll_protocol> endpoint;

	int type() const { return SOCK_RAW; }
	int protocol() const { return protocol_; }
	int family() const { return family_; }
	ll_protocol(int protocol, int family)
	    : protocol_(protocol), family_(family) {}
	ll_protocol() : protocol_(htons(ETH_P_ALL)), family_(PF_PACKET) {}

    private:
	int protocol_;
	int family_;
};

class IO {
    public:
	typedef boost::asio::basic_raw_socket<ll_protocol> socket;
	typedef ll_endpoint<ll_protocol> endpoint;
	IO(boost::asio::io_context& io_context, char* ifname)
	    : socket_(io_context, endpoint(ifname)), sender_endpoint_(ifname) {
		/* subscribing to ISIS multicast */
		packet_mreq mreq;
		memset(&mreq, 0, sizeof(mreq));
		mreq.mr_ifindex = if_nametoindex(ifname);
		mreq.mr_type = PACKET_MR_MULTICAST;
		mreq.mr_alen = ETH_ALEN;
		memcpy(&mreq.mr_address, ALL_ISS, ETH_ALEN);
		setsockopt(socket_.native_handle(), SOL_PACKET,
			   PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
		/* filtering host addressed traffic */
		struct sock_filter bpf_bytecode[] = {
		    {0x20, 0, 0, 0x00000002}, {0x15, 0, 3, 0x2b000005},
		    {0x28, 0, 0, 0x00000000}, {0x15, 0, 1, 0x00000900},
		    {0x6, 0, 0, 0x00040000},  {0x6, 0, 0, 0x00000000},
		};
		struct sock_fprog bpf_program = {
		    sizeof(bpf_bytecode) / sizeof(bpf_bytecode[0]),
		    bpf_bytecode};
		setsockopt(socket_.native_handle(), SOL_SOCKET,
			   SO_ATTACH_FILTER, &bpf_program, sizeof(bpf_program));
	}
        IO(const IO& other) = delete;
        IO(IO&& other) = delete;
        IO& operator=(IO&& other) = delete; 

	void  do_receive() {
		    socket_.async_receive_from(
		    data_.prepare(max_length), sender_endpoint_,
		    [this](boost::system::error_code ec,
			   std::size_t bytes_recvd) {
			    if (ec && bytes_recvd <= 0 && ec.value() != 125) {
				    std::cout << "Error on receive " << ec 
				    	      << std::endl;
			    }
			    data_.commit(bytes_recvd);
                            #ifdef DEBUG
			    std::cout << "Bytes received:" << bytes_recvd
				      << std::endl;
			    std::cout << "Buffer size:" << data_.size()
				      << std::endl;
			    boost::asio::streambuf temp;
			    std::size_t bytes_copied = buffer_copy(
				temp.prepare(bytes_recvd), data_.data());
			    temp.commit(bytes_copied);
			    hex_dump(
				std::cout,
				std::string(
				    (std::istreambuf_iterator<char>(&temp)),
				    std::istreambuf_iterator<char>()));
                            #endif
		    });
	}

	void do_send(boost::asio::streambuf* send_data_) {
		socket_.async_send_to(
		    send_data_->data(), sender_endpoint_,
		    [this](boost::system::error_code, std::size_t) {});
	}
	boost::asio::streambuf* get_data() { return &data_; };

        void do_stop() {
             socket_.close();     

        }


    private:
	enum { max_length = 1500 };
	boost::asio::streambuf data_;
        endpoint sender_endpoint_;
        socket socket_;
};

