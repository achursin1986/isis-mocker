#pragma once
#include <atomic>
#include <ctime>
#include <iomanip>

#include "flooder.hpp"
#include "fsm.hpp"
#include "io.hpp"
#include "tester.hpp"
#include "utils.hpp"


#include <boost/asio.hpp>



void fill_params(struct Params& params, std::string sysid_str, std::string ip_str, std::string area_str) {
        /* sysid */
        boost::erase_all(sysid_str, ".");
        for (int j = 0, k = 0; j < 6 && k < 12; ++j, k += 2) {
                params.SYS_ID_[j] = static_cast<unsigned char>(std::stoi(sysid_str.substr(k, 2), 0, 16));
                params.LSP_ID_[j] = static_cast<unsigned char>(std::stoi(sysid_str.substr(k, 2), 0, 16));
        }

        /* ip */
        std::memcpy(params.IP_ADDRESS_, ip_to_bytes(ip_str).get(),4);

        /* area */
        boost::erase_all(area_str, ".");
        std::memcpy(params.AREA_, area_to_bytes(area_str).get(), area_str.size() / 2);
        params.area_size = area_str.size() / 2;
}



#define ONE_DISPATCH(Z, Iter, Data)         \
	case Iter:                          \
		send_event<Iter, E>(event); \
		break;

template <typename E>
void dynamic_dispatch(int id, E& event) {
	switch (id) {
		BOOST_PP_REPEAT_FROM_TO(0, SM_PARK_SIZE, ONE_DISPATCH, % %);
		default:
			break;
	}
}


class Mocker {
    public:
	Mocker(char* ifname, int id, const std::string& sysid, const std::string& ip, const std::string& area)
	    : io_(io_context_, &ifname[0]), id_(id), holdtimer_(timer_) {
		fill_params(params_, sysid, ip, area);
		terminate = false;
		packet_th_ = std::thread([&] {
			while (!terminate) {
				io_.do_receive();
                                
                                holdtimer_.expires_from_now(boost::posix_time::seconds(30));
                                holdtimer_.async_wait([&](const boost::system::error_code& ec) {
                                          if ( ec.value() == 0 ) {
                                              TIMEOUT to;
                                              to.state = &state_;
                                              to.flooder = params_.flooder;
                                              to.print = false;
                                              dynamic_dispatch<TIMEOUT>(id_, to);
                                          }
                                    });
                               
                                auto t = std::thread([&]{ timer_.run();});
                                io_context_.run();
      
                                holdtimer_.expires_from_now(boost::posix_time::milliseconds(1));
                                holdtimer_.async_wait([&](const boost::system::error_code& ec){});

				ISIS_PKT packet;
				stats_.packets_in++;
				std::size_t bytes_copied =
				    buffer_copy(packet.data_.prepare(io_.get_data()->size()), io_.get_data()->data());
				packet.data_.commit(bytes_copied);
				io_.get_data()->consume(bytes_copied);
				packet.endpoint = &io_;
				packet.stats = &stats_;
				{
					std::unique_lock<std::mutex> lock(ptr_guard);
					packet.params = &params_;
					packet.state = &state_;
					dynamic_dispatch<ISIS_PKT>(id_, packet);
				}
                                io_context_.reset();
                                t.join();
                                timer_.reset();
			};
		});
	}
	Mocker(Mocker& other) = delete;
	Mocker(Mocker&& other) = delete;
	Mocker& operator=(Mocker&& other) = delete;

	~Mocker() {
		terminate = true;
		io_.do_stop();
		io_context_.stop();
		holdtimer_.cancel();
                timer_.reset();

		TIMEOUT to;
		to.state = &state_;
		to.print = false;
		dynamic_dispatch<TIMEOUT>(id_, to);

		packet_th_.join();
	}

	void clear_stats() { stats_.reset(); }

	IO& get_io() { return io_; }

	int get_id() { return id_; }

	std::atomic_bool& get_state() { return state_; }

	Stats& get_stats() { return stats_; }

	void register_flooder(Flooder* flooder) {
		std::unique_lock<std::mutex> lock(ptr_guard);
		params_.flooder = flooder;
	}
	void unregister_flooder() {
		std::unique_lock<std::mutex> lock(ptr_guard);
		params_.flooder = nullptr;
	}

	void register_tester(Tester* tester) {
		std::unique_lock<std::mutex> lock(ptr_guard);
		params_.tester = tester;
	}
	void unregister_tester() {
		std::unique_lock<std::mutex> lock(ptr_guard);
		params_.tester = nullptr;
	}

	void print_stats(std::ostream& out) {
		out << " Mocker " << id_ << std::endl;
		int hrs{}, min{}, sec{};
		if (state_) {
			double uptime = std::difftime(std::time(nullptr), stats_.up_time);
			if (uptime > 0) {
				hrs = (int)uptime / 3600;
				min = ((int)uptime % 3600) / 60;
				sec = ((int)uptime % 3600) % 60;
			}
			out << " State: Up" << std::endl;
			out << " Uptime: " << std::setw(2) << std::setfill('0') << hrs << ":" << std::setw(2) << std::setfill('0')
				  << min << ":" << std::setw(2) << std::setfill('0') << sec << std::endl;

		} else {
			out << " State: Down" << std::endl;
		}
		if (params_.flooder != nullptr) out << " Flooder attached" << std::endl;
		if (params_.tester != nullptr) out << " Tester attached" << std::endl;
		out << " Stats: " << std::endl;
		out << "       "
			  << "hello in      " << stats_.hello_in << std::endl;
		out << "       "
			  << "hello out     " << stats_.hello_out << std::endl;
		out << "       "
			  << "pkts in       " << stats_.packets_in << std::endl;
		out << "       "
			  << "pkts out      " << stats_.packets_out << std::endl;
		if (params_.flooder != nullptr)
			out << "       "
				  << "lsp announced " << params_.flooder->get_stats().lsp_announced << std::endl;
		if (params_.tester != nullptr)
			out << "       "
				  << "test cycles " << params_.tester->get_stats().cycles / 2 << std::endl;
	}

    private:
	boost::asio::io_context io_context_,timer_;
	boost::asio::deadline_timer holdtimer_;
	IO io_;
	std::thread packet_th_;
	Stats stats_;
	Params params_;
	std::mutex ptr_guard;
	int id_;
	std::atomic_bool terminate, state_, timer;
};

