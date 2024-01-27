#pragma once
#include <stdio.h>

#include <algorithm>
#include <mutex>

#include "flooder.hpp"
#include "fsm.hpp"
#include "mocker.hpp"
#include "parser.hpp"

void show_database(const auxdb& db, std::ostream& out) {
	int paginator{};
	std::string in = "";
	out << "       sysid         hostname" << std::endl;
	for (auto i = db.begin(); i != db.end(); i++) {
		if ((*i).second.get()->NEIGHBORS_.size()) {
			out << "      " << (*i).first << " " << (*i).second.get()->HOSTNAME_ << std::endl;
			++paginator;
			if (paginator > 25) {
				paginator = 0;
				out << "<<press Enter for more>>" << std::endl;
				fgetc(stdin);
				std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
			}
		}
	}
}

void show_sysid(const auxdb& db,const  std::string& sysid, std::ostream& out) {
	int paginator{};
	std::string in = "";
	if (db.find(sysid) == db.end()) {
		out << "Incorrect id or not found" << std::endl;
		return;
	}

	if (db.at(sysid).get()->NEIGHBORS_.size()) {
		out << db.at(sysid).get()->HOSTNAME_ << std::endl;
		out << "area: " << std::endl;
		out << db.at(sysid).get()->AREA_ << std::endl;
		if (db.at(sysid).get()->NEIGHBORS_.size()) out << "neighbors: " << std::endl;
		for (auto k : db.at(sysid).get()->NEIGHBORS_) {
			out << "      " << k.second.first << " <--- " << k.second.second << " " << k.first << std::endl;
		}
		out << "prefixes: " << std::endl;
		for (const auto& k : db.at(sysid).get()->SUBNETS_) {
			out << "      " << k << std::endl;
			++paginator;
			if (paginator > 25) {
				paginator = 0;
				out << "<<press Enter for more>>" << std::endl;
				fgetc(stdin);
				std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
			}
		}

		out << std::endl;
	}
}

void show_mockers(const std::vector<std::unique_ptr<Mocker>>& mockers, std::ostream& out) {
	for (auto i = mockers.begin(); i != mockers.end(); i++) (*i).get()->print_stats(out);
}

void clear_stats(std::vector<std::unique_ptr<Mocker>>& mockers) {
	for (auto i = mockers.begin(); i != mockers.end(); i++) (*i).get()->clear_stats();
}

void show_interfaces(const std::vector<std::string>& ifnames, std::unordered_set<std::string>& ifnames_used, std::ostream& out) {
	out << "Interfaces:" << std::endl;
	for (const auto& k : ifnames) {
		out << "      " << k << std::endl;
	}
	out << "Used:" << std::endl;
	for (const auto& k : ifnames_used) {
		out << "      " << k << std::endl;
	}
}

void mock(std::unordered_map<std::string, std::string>& lsdb, std::mutex& db_mtx, const std::string& sysid,
	  std::pair<std::string, std::string>& mocked, std::ostream& out) {
	std::unique_lock<std::mutex> lock(db_mtx);
	std::string lspid = sysid + ".00-00";
	if (lsdb.find(lspid) == lsdb.end()) {
		out << "Incorrect sysid or not found" << std::endl;
		return;
	}
	if (mocked.first.length() || mocked.second.length()) {
		out << "Already present mocked instance" << std::endl;
		return;
	}
	mocked.first = lspid;
	mocked.second = lsdb[lspid];
	lsdb.erase(lspid);
}

void mocker_start(int id, std::string ifname, std::string sysid, std::string area, std::string ip,
		  std::vector<std::unique_ptr<Mocker>>& mockers, std::vector<std::string>& ifnames,
		  std::unordered_set<std::string>& used_ifnames, std::unordered_set<int>& used_ids,
		  std::pair<std::string, std::string>& mocked_lsp, std::ostream& out) {
	if (id < 0 || id >= SM_PARK_SIZE) {
		out << "Incorrect index, use indecies 0 to " << SM_PARK_SIZE << std::endl;
		return;
	}
	if (!ifname.size() || !sysid.size() || !area.size() || !ip.size()) {
		out << "Empty params are not allowed, follow standard notations for parameters" << std::endl;
		return;
	}
	bool found{false};
	for (auto k : ifnames) {
		if (k == ifname) found = true;
	}

	if (!found) {
		out << "Provided ifname is not on the list" << std::endl;
		return;
	}

	if (used_ifnames.count(ifname) || used_ids.count(id)) {
		out << "id or ifname is/are used already" << std::endl;
		return;
	}
	if (!mocked_lsp.first.size() || !mocked_lsp.second.size()) {
		out << "Need to mock first" << std::endl;
		return;
	}

	std::unique_ptr<Mocker> temp(new Mocker(const_cast<char*>(ifname.c_str()), id, sysid, ip, area));
	mockers.push_back(std::move(temp));

	used_ifnames.insert(ifname);
	used_ids.insert(id);
}

void flood_start(int id, std::unordered_map<std::string, std::string>& lsdb, std::vector<std::unique_ptr<Flooder>>& flooders,
		 std::vector<std::unique_ptr<Mocker>>& mockers,std::ostream& out) {
	if (mockers.empty()) {
		out << "Need to add mockers first" << std::endl;
		return;
	}
	bool found{false};
	for (auto i = mockers.begin(); i != mockers.end(); i++) {
		if ((*i).get()->get_id() == id) {
			bool update;
			if (flooders.empty())
				update = true;
			else
				update = false;

			std::unique_ptr<Flooder> temp(new Flooder(id, lsdb, (*i).get()->get_io(), (*i).get()->get_state(), update));
			flooders.push_back(std::move(temp));
			(*i).get()->register_flooder(flooders.back().get());
			found = true;
		}
	}
	if (!found) out << "Mocker was not found" << std::endl;
}

void test_start(int id, std::unordered_map<std::string, std::string>& lsdb, std::unordered_map<std::string, std::string>& testdb,
		std::vector<std::unique_ptr<Flooder>>& flooders, std::vector<std::unique_ptr<Mocker>>& mockers,
		std::vector<std::unique_ptr<Tester>>& testers, int test_interval, std::ostream& out) {
	if (testers.size() > 0) {
		out << "Tester is already running" << std::endl;
		return;
	}
	if (mockers.empty()) {
		out << "Need to add mockers first" << std::endl;
		return;
	}
	if (flooders.empty()) {
		out << "Need to add flooders first" << std::endl;
		return;
	}
	if (testdb.empty()) {
		out << "Diff is empty" << std::endl;
		return;
	}
	if (test_interval <= 50 || test_interval > 5000) {
		out << "Out of range interval" << std::endl;
		return;
	}

	bool found{false};
	for (auto i = mockers.begin(); i != mockers.end(); i++) {
		if ((*i).get()->get_id() == id) {
			std::unique_ptr<Tester> temp(
			    new Tester(id, lsdb, (*i).get()->get_io(), (*i).get()->get_state(), testdb, test_interval));
			testers.push_back(std::move(temp));
			(*i).get()->register_tester(testers.back().get());
			found = true;
		}
	}
	if (!found) out << "Mocker was not found" << std::endl;
}

void test_clear(std::vector<std::unique_ptr<Tester>>& testers) { testers.clear(); }

void reset_all(std::vector<std::unique_ptr<Mocker>>& mockers, std::vector<std::unique_ptr<Flooder>>& flooders,
	       std::vector<std::unique_ptr<Tester>>& testers, std::unordered_set<std::string>& used_ifnames,
	       std::unordered_set<int>& used_ids, std::unordered_map<std::string, std::string>& lsdb,
	       std::pair<std::string, std::string>& mocked) {
	std::cout << "Destroying... " << std::endl;
	/* put back mocked lsp */
	if (mocked.first.length() && mocked.second.length()) lsdb.insert(mocked);
	mocked.first = "";
	mocked.second = "";
	/* clear floods and test*/
	testers.clear();
	flooders.clear();
	mockers.clear();

	used_ifnames.clear();
	used_ids.clear();
	std::cout << "done" << std::endl;
}

void prepare_test(std::unordered_map<std::string, std::string>& lsdb, std::unordered_map<std::string, std::string>& testdb,
		  const std::string& file_json2, const std::string& file_json_raw2, const std::string& file_json_hostname, std::ostream& out ) {
	testdb.clear();
	std::unordered_map<std::string, std::string> LSDB2;
	auxdb AUXDB2;

	try {
		parse(LSDB2, AUXDB2, file_json2, file_json_raw2, file_json_hostname);
		out << "Loaded json2" << std::endl;
		malloc_trim(0);

		for (auto i = lsdb.begin(); i != lsdb.end(); i++) {
			auto size = std::min((*i).second.length(), LSDB2[(*i).first].length());
			bool diff{false};
			for (int j = 42; j < int(size); j++)
				if (((*i).second)[j] != (LSDB2[(*i).first])[j]) {
					diff = true;
					break;
				}
			/* check if there is a diff between LSDBs*/
			if (LSDB2.count((*i).first) && (*i).second.length() != LSDB2[(*i).first].length() && diff) {
				std::string tempkey = (*i).first;
				std::string temp = LSDB2[tempkey];
				testdb.insert(std::make_pair<std::string, std::string>(std::move(tempkey), std::move(temp)));
			}
		}

		if (testdb.empty())
			out << "No diff found" << std::endl;
		else {
			out << "Diff:" << std::endl;
			for (auto k : testdb) std::cout << "       " << k.first << std::endl;
			out << "Ready to start test" << std::endl;
		}

	} catch (const std::exception& e) {
		std::cerr << "Error while parsing file, exception: " << e.what() << std::endl;
	}
}

