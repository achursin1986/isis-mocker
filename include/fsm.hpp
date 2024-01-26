#pragma once
#include <boost/asio.hpp>
#include <boost/preprocessor.hpp>
#include <iostream>
#include <istream>
#include <ostream>
#include <chrono>

#include "io.hpp"
#include "isis.hpp"
#include "tinyfsm.hpp"
#include "utils.hpp"
#include "flooder.hpp"
#include "tester.hpp"

#define SM_PARK_SIZE 50
#define LIST_SMs(Z, Iter, data) ISIS_ADJ<Iter>
#define ONE_SM(Z,Iter,Data) \
    FSM_INITIAL_STATE(ISIS_ADJ<Iter>, Down<Iter>);

extern  bool DEBUG_PRINT;


struct Stats {

      Stats() { reset(); }

      void reset() {
          packets_in = 0;
          packets_out = 0;
          hello_in = 0;
          hello_out = 0;
          up_time = std::numeric_limits<std::time_t>::max();
      }


      long packets_in;
      long packets_out;
      long hello_in;
      long hello_out;
      std::time_t up_time;
};

struct Params {

        Params() {
           std::fill(AREA_,AREA_+13,0);
           std::fill(SYS_ID_,SYS_ID_+6,0);
           std::fill(IP_ADDRESS_,IP_ADDRESS_+4,0);
           std::fill(LSP_ID_,LSP_ID_+8,0);
           flooder = nullptr;
           tester = nullptr;
        }

        unsigned char AREA_[13];
        unsigned char LSP_ID_[8];
        unsigned char SYS_ID_[6];
        unsigned char IP_ADDRESS_[4];
        unsigned char MASK;
        int area_size;
        Flooder* flooder;
        Tester* tester;
};




struct PKT : tinyfsm::Event {
	boost::asio::streambuf data_;
	IO* endpoint;
        Stats* stats;
        Params* params; 
        std::atomic_bool* state; 
};

struct TIMEOUT : tinyfsm::Event {
        bool print{true};
        std::atomic_bool* state;
        Flooder* flooder;

};

struct ISIS_PKT : PKT {};

template <int id>
class ISIS_ADJ : public tinyfsm::Fsm<ISIS_ADJ<id>> {
    public:
	virtual void react(ISIS_PKT&){};
	virtual void react(TIMEOUT&){};
	virtual void entry(){};
	virtual void exit(){};
};

template <int id>
class Down : public ISIS_ADJ<id> {
	void entry() override {
                if (DEBUG_PRINT) std::cout << "ISIS-"<< id << " Adj is : Down" << std::endl;
	};
	void react(ISIS_PKT& e) override;
};

template <int id>
class Init : public ISIS_ADJ<id> {
	void entry() override {
		if (DEBUG_PRINT) std::cout << "ISIS-"<< id << " Adj is : Init" << std::endl;
	};
	void react(ISIS_PKT& e) override;
};

template <int id>
class Up : public ISIS_ADJ<id> {
	void entry() override { if (DEBUG_PRINT) std::cout << "ISIS-" << id << " Adj is : Up" << std::endl;};
	void react(ISIS_PKT& e) override;
	void react(TIMEOUT& e) override;
};

template<int id>
void Down<id>::react(ISIS_PKT& e) {
        std::istream packet_r(&e.data_);
	eth_header hdr_0_r;   
	isis_header hdr_1_r;
	isis_hello_header hdr_2_r;
	tlv_240 payload_0_r;
	packet_r >> hdr_0_r >> hdr_1_r >> hdr_2_r >> payload_0_r;
        e.stats->packets_in++;

	/*  send hello with Init filling neighbor data */
	if ((hdr_1_r.pdu_type() == p2p_hello) &&
	    (payload_0_r.adjacency_state() == down)) {
                #ifdef DEBUG
		std::cout << "Got hello packet in Down state "<< id  << std::endl;
                #endif
                e.stats->hello_in++;
		boost::asio::streambuf packet;
		std::ostream os(&packet);
		eth_header hdr_0;
		isis_header hdr_1; 
		isis_hello_header hdr_2;
                hdr_2.system_id(e.params->SYS_ID_); 
		tlv_240_ext payload_0;
		tlv_129 payload_1;
		tlv_132 payload_2;
                payload_2.ip_address(e.params->IP_ADDRESS_);
		tlv_1_ext payload_3;                
                payload_3.area(e.params->AREA_,e.params->area_size);
                payload_3.area_length(e.params->area_size);
                payload_3.tlv_length(e.params->area_size+1);
                
 
                /* MT so far not tested with raw db but should be ok to add */
 
                 /* payload_4 
                tlv_229 mt;
                tlv_229_topology ipv4_topo;
                ipv4_topo.topology(0);
                tlv_229_topology ipv6_topo;
                ipv6_topo.topology(2);
                mt.tlv_length(4); */     

		payload_0.neighbor_sysid(hdr_2_r.system_id());
		payload_0.ext_neighbor_local_circuit_id(
		    payload_0_r.ext_local_circuit_id());
		hdr_1.pdu_type(p2p_hello);
		hdr_1.length_indicator(20);
		/* length accounts LLC part */
		hdr_0.length(sizeof(hdr_1) + sizeof(hdr_2) + sizeof(payload_0) +
			     sizeof(payload_1) + sizeof(payload_2) +
			     3 + e.params->area_size + 3);  // +6 MT 
		hdr_2.pdu_length(sizeof(hdr_1) + sizeof(hdr_2) +
				 sizeof(payload_0) + sizeof(payload_1) +
				 sizeof(payload_2) + 3 + e.params->area_size);

		os << hdr_0 << hdr_1 << hdr_2 << payload_0 << payload_1
		   << payload_2 << payload_3; // << mt << ipv4_topo << ipv6_topo;  

		e.endpoint->do_send(&packet);
                e.stats->hello_out++;
                e.stats->packets_out++;
		ISIS_ADJ<id>::template transit<Init<id>>();
	}
}

template <int id>
void Init<id>::react(ISIS_PKT& e) {
        std::istream packet_r(&e.data_);
	eth_header hdr_0_r;
	isis_header hdr_1_r;
	isis_hello_header hdr_2_r;
	tlv_240_ext payload_0_r;
	packet_r >> hdr_0_r >> hdr_1_r >> hdr_2_r >> payload_0_r;
        e.stats->packets_in++;
	/* check if we are known by him */
	if ((hdr_1_r.pdu_type() == p2p_hello) &&
	    (payload_0_r.adjacency_state() == init) &&
	    (std::equal(e.params->SYS_ID_,e.params->SYS_ID_ + 6,   
			payload_0_r.neighbor_sysid()))) {
                e.stats->hello_in++;
                #ifdef DEBUG
		std::cout << "Got hello packet in Init " << id << std::endl;
                #endif
		boost::asio::streambuf packet;
		std::ostream os(&packet);
		eth_header hdr_0; 
		isis_header hdr_1;
		isis_hello_header hdr_2;
                hdr_2.system_id(e.params->SYS_ID_);
		tlv_240_ext payload_0;
		tlv_129 payload_1;
		tlv_1_ext payload_2;
                payload_2.area(e.params->AREA_,e.params->area_size);
                payload_2.area_length(e.params->area_size);
                payload_2.tlv_length(e.params->area_size+1);
		tlv_132 payload_3;
                payload_3.ip_address(e.params->IP_ADDRESS_);  
                 /* payload_4 
                tlv_229 mt;
                tlv_229_topology ipv4_topo;
                ipv4_topo.topology(0);
                tlv_229_topology ipv6_topo;
                ipv6_topo.topology(2);
                mt.tlv_length(4);
                */

		/* flip to up */
		payload_0.adjacency_state(up);
		payload_0.neighbor_sysid(hdr_2_r.system_id());
		payload_0.ext_neighbor_local_circuit_id(
		    payload_0_r.ext_local_circuit_id());
		hdr_1.pdu_type(p2p_hello);
		hdr_1.length_indicator(20);
		hdr_0.length(sizeof(hdr_1) + sizeof(hdr_2) + sizeof(payload_0) +
			     sizeof(payload_1) + 3+e.params->area_size +
			     sizeof(payload_3) + 3);
		hdr_2.pdu_length(sizeof(hdr_1) + sizeof(hdr_2) +
				 sizeof(payload_0) + sizeof(payload_1) +
				 3+e.params->area_size + sizeof(payload_3));  // +6 mt

		os << hdr_0 << hdr_1 << hdr_2 << payload_0 << payload_1
		   << payload_2 << payload_3; //<< mt << ipv4_topo << ipv6_topo;

		e.endpoint->do_send(&packet);
                e.stats->hello_out++;
                e.stats->packets_out++;
                e.stats->up_time = std::time(nullptr); 
                *e.state = true;
                if (e.params->flooder != nullptr  ) e.params->flooder->start();
                ISIS_ADJ<id>::template transit<Up<id>>();
	} else {
               
                *e.state = false;
                if (e.params->flooder != nullptr  ) e.params->flooder->stop();
		ISIS_ADJ<id>::template transit<Down<id>>();
	}
}

template <int id>
void Up<id>::react(ISIS_PKT& e) {
        std::istream packet_r(&e.data_);
	eth_header hdr_0_r;
	isis_header hdr_1_r;
	isis_hello_header hdr_2_r;
	tlv_240_ext payload_0_r;
	packet_r >> hdr_0_r >> hdr_1_r >> hdr_2_r >> payload_0_r;
        e.stats->packets_in++;
	/* CSNP and CSNP support from neighbor is not required for now, will be
	 * added later */

	if ((hdr_1_r.pdu_type() == p2p_hello) && (payload_0_r.adjacency_state() == up) ) {
                #ifdef DEBUG
		std::cout << "Got hello packet in Up " << id << std::endl;
                #endif
                e.stats->hello_in++;
		boost::asio::streambuf packet;
		std::ostream os(&packet);
		eth_header hdr_0;
		isis_header hdr_1;
		isis_hello_header hdr_2;
                hdr_2.system_id(e.params->SYS_ID_);
		tlv_240_ext payload_0;
		tlv_129 payload_1;
		tlv_1_ext payload_2;
                payload_2.area(e.params->AREA_,e.params->area_size);
                payload_2.area_length(e.params->area_size);
                payload_2.tlv_length(e.params->area_size+1);
		tlv_132 payload_3;
                payload_3.ip_address(e.params->IP_ADDRESS_);
                /* payload_4 
                tlv_229 mt;
                tlv_229_topology ipv4_topo;
                ipv4_topo.topology(0);
                tlv_229_topology ipv6_topo;
                ipv4_topo.topology(2);
                mt.tlv_length(4);
                */ 
  


		/* flip to up */
		payload_0.adjacency_state(up);
		payload_0.neighbor_sysid(hdr_2_r.system_id());
		payload_0.ext_neighbor_local_circuit_id(
		    payload_0_r.ext_local_circuit_id());
		hdr_1.pdu_type(p2p_hello);
		hdr_1.length_indicator(20);
		hdr_0.length(sizeof(hdr_1) + sizeof(hdr_2) + sizeof(payload_0) +
			     sizeof(payload_1) + 3 + e.params->area_size  +
			     sizeof(payload_3) + 3);
		hdr_2.pdu_length(sizeof(hdr_1) + sizeof(hdr_2) +
				 sizeof(payload_0) + sizeof(payload_1) +
				 3+ e.params->area_size + sizeof(payload_3)); //+6 mt

		os << hdr_0 << hdr_1 << hdr_2 << payload_0 << payload_1
		   << payload_2 << payload_3; // << mt << ipv4_topo << ipv6_topo;

		e.endpoint->do_send(&packet);
                e.stats->hello_out++;
                e.stats->packets_out++;
                *e.state = true;

	} else if ((hdr_1_r.pdu_type() == l2_lsp) ||
		   (hdr_1_r.pdu_type() == l2_csnp) ||
		   (hdr_1_r.pdu_type() == l2_psnp)) {
		/* if CSNP or LSP need to send empty CSNP as we don't store data
		 * for hello  */         // need to send hello here as well
		boost::asio::streambuf packet;
		std::ostream os(&packet);
		eth_header hdr_0;
		isis_header hdr_1;
		isis_csnp_header hdr_2;
                hdr_2.source_id(e.params->LSP_ID_);
		//tlv_9 payload_0;
                //isis_csnp_1lsp payload_0;
		hdr_1.pdu_type(l2_csnp);
                hdr_2.pdu_length(sizeof(hdr_1) + sizeof(hdr_2)); //+ sizeof(payload_0));
		hdr_1.length_indicator(33);
		hdr_0.length(3 + sizeof(hdr_1) + sizeof(hdr_2)); //+ sizeof(payload_0));
		os << hdr_0 << hdr_1 << hdr_2; //<< payload_0;
		e.endpoint->do_send(&packet);
                e.stats->packets_out++;

	} else {
	        if (DEBUG_PRINT) std::cout << "ISIS-"<< id << " Peer is not Up. Going Down." << std::endl;
                *e.state = false;
                if (e.params->flooder != nullptr  ) e.params->flooder->stop();
		ISIS_ADJ<id>::template transit<Down<id>>();
	}
}

template <int id>
void Up<id>::react(TIMEOUT& e) {
       if ( e.print ) { std::cout << std::endl;
         if (DEBUG_PRINT) std::cout << "Hold-time expired. Going Down." << std::endl; }
         *e.state = false;
        if (e.flooder != nullptr  ) e.flooder->stop();
	ISIS_ADJ<id>::template transit<Down<id>>();
        (void)e;
}


template <int id, typename E>
void send_event(E& event) { 
          ISIS_ADJ<id>::template dispatch<E>(event);
}

/* SMs sharing park */

using fsm_list = tinyfsm::FsmList<BOOST_PP_ENUM(SM_PARK_SIZE, LIST_SMs, %%)>;
BOOST_PP_REPEAT_FROM_TO(0,SM_PARK_SIZE, ONE_SM, %%);
