#pragma once
#include <iostream>
#include <string>

#include "utils.hpp"

struct TesterStats {
	long cycles{0};
};

void send_db(std::unordered_map<std::string, std::string>& lsdb, IO& io) {
	for (auto const& [key, value] : lsdb) {
		boost::asio::streambuf sbuf;
		std::iostream os(&sbuf);
		sbuf.prepare(value.size());
		os << value;
		io.do_send(&sbuf);
		inc_sequence_num(lsdb, key, value, 1);
	}
}

class Tester {
    public:
	Tester(Tester& other) = delete;
	Tester(Tester&& other) = delete;
	Tester& operator=(Tester&& other) = delete;

	Tester(int id, std::unordered_map<std::string, std::string>& lsdb, IO& io, std::atomic_bool& state,
	       std::unordered_map<std::string, std::string>& testdb, int test_interval)
	    : lsdb_(lsdb), testdb_(testdb), mocker_id_(id), io_(io), state_(state), test_interval_(test_interval) {
		tester_th_ = std::thread([&]() {
			/* sync seq numbers in testdb */
			for (auto i = testdb.begin(); i != testdb.end(); i++) {
				inc_sequence_num(lsdb, (*i).first, (*i).second, 1000);
			}
			/* making test samples based on testdb */
			std::unordered_map<std::string, std::string> test_sample1;
			std::unordered_map<std::string, std::string> test_sample2;

			for (auto k : testdb_) {
				auto key = k.first;
				auto key2 = key;
				auto value = k.second;
				auto value2 = lsdb_[key];
				std::string stripped = key;
				test_sample1.insert(std::make_pair<std::string, std::string>(std::move(key), std::move(value2)));
				test_sample2.insert(std::make_pair<std::string, std::string>(std::move(key2), std::move(value)));
				for (int i = 0; i < 6; i++) stripped.pop_back();

				for (auto l : lsdb_) {
					if (l.first.find(stripped) != std::string::npos) {
						auto first = l.first;
						auto second = l.second;
						auto first2 = first;
						auto second2 = second;
						test_sample1.insert(
						    std::make_pair<std::string, std::string>(std::move(first), std::move(second)));
						test_sample2.insert(
						    std::make_pair<std::string, std::string>(std::move(first2), std::move(second2)));
					}
				}
			}

			while (!terminate) {
				if (stats_.cycles % 2) {
					if (state_) {
						send_db(test_sample1, io_);
					}

				} else {
					if (state_) {
						send_db(test_sample2, io_);
					}
				}
				stats_.cycles++;
				std::this_thread::sleep_for(std::chrono::milliseconds(test_interval_));
			}
		});
	}

	TesterStats& get_stats() { return stats_; }

	~Tester() {
		terminate = true;
		test_interval_ = 1;
		tester_th_.join();
	}

    private:
	std::thread tester_th_;
	IO& io_;
	TesterStats stats_;
	std::unordered_map<std::string, std::string>&lsdb_, testdb_;
        int mocker_id_, test_interval_;
	std::atomic_bool terminate{false}, &state_;
};
